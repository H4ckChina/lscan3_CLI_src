#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_BLOCK 1048576U
#define MAX_LINE 256
#define DEFAULT_TIMEOUT_MS 3000
#define DEFAULT_THREADS 4
#define THREAD_STACK_SIZE (256U * 1024U)

struct target { char ip[INET_ADDRSTRLEN]; };
struct port_file { char name[256]; int port; };

struct global_stats {
    size_t checked;
    size_t found;
    size_t total;
    struct timespec started;
    pthread_mutex_t lock;
};

struct job {
    struct target *targets;
    size_t count;
    size_t next;
    size_t completed;
    size_t found;
    int port;
    int timeout_ms;
    const char *output;
    struct global_stats *g;
    struct timespec started;
    pthread_mutex_t lock;
};

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s -i input_dir [-o output_dir] [-t threads] [-w timeout_ms]\n", name);
    fprintf(stderr, "  input_dir contains port-named files such as 4899.txt\n");
}

static double elapsed_seconds(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) +
           (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}

static void format_eta(double seconds, char *out, size_t size) {
    unsigned long total;
    if (seconds < 0.0 || seconds > 864000000.0) {
        snprintf(out, size, "unknown");
        return;
    }
    total = (unsigned long)(seconds + 0.5);
    snprintf(out, size, "%02lu:%02lu:%02lu", total / 3600, (total / 60) % 60, total % 60);
}

static int mkdir_one(const char *path) {
    return (mkdir(path, 0755) == 0 || errno == EEXIST) ? 0 : -1;
}

static int mkdir_output(const char *base, const char *version, char *dir, size_t n) {
    if (mkdir_one(base) < 0) return -1;
    if (snprintf(dir, n, "%s/%s", base, version) >= (int)n) return -1;
    return mkdir_one(dir);
}

static int wait_fd(int fd, int writing, int timeout_ms) {
    struct pollfd pfd;
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = writing ? POLLOUT : POLLIN;
    for (;;) {
        int rc = poll(&pfd, 1, timeout_ms);
        if (rc > 0) {
            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) return 0;
            return (pfd.revents & pfd.events) != 0;
        }
        if (rc == 0) return 0;
        if (errno != EINTR) return 0;
    }
}

static int read_full(int fd, void *buf, size_t len, int timeout_ms) {
    size_t done = 0;
    while (done < len) {
        ssize_t n;
        if (!wait_fd(fd, 0, timeout_ms)) return 0;
        n = recv(fd, (char *)buf + done, len - done, 0);
        if (n <= 0) return 0;
        done += (size_t)n;
    }
    return 1;
}

static int write_full(int fd, const void *buf, size_t len, int timeout_ms) {
    size_t done = 0;
    while (done < len) {
        ssize_t n;
        if (!wait_fd(fd, 1, timeout_ms)) return 0;
        n = send(fd, (const char *)buf + done, len - done, MSG_NOSIGNAL);
        if (n <= 0) return 0;
        done += (size_t)n;
    }
    return 1;
}

static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t radmin_crc(const unsigned char *p, size_t len) {
    uint32_t sum = 0;
    while (len) {
        size_t take = len < 4 ? len : 4;
        uint32_t word = 0;
        for (size_t i = 0; i < take; ++i) {
            word |= (uint32_t)p[i] << (8 * i);
        }
        sum += word;
        p += take;
        len -= take;
    }
    return sum;
}

static int connect_target(const char *ip, int port, int timeout_ms) {
    int fd, flags, rc;
    struct sockaddr_in sa;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(fd);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    if (rc < 0) {
        int error = 0;
        socklen_t elen = sizeof(error);
        if (!wait_fd(fd, 1, timeout_ms) ||
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &elen) < 0 || error) {
            close(fd);
            return -1;
        }
    }

    if (fcntl(fd, F_SETFL, flags) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int probe(const char *ip, int port, int timeout_ms, char *version, size_t version_len) {
    unsigned char header[9], block[1] = { 0x08 }, *response = NULL;
    int fd = connect_target(ip, port, timeout_ms);
    uint32_t block_len, sent_crc, actual_crc;
    int result = 0;

    if (fd < 0) return 0;

    {
        unsigned char out[9];
        uint32_t len = htonl(1);
        uint32_t crc = htonl(radmin_crc(block, 1));

        out[0] = 1;
        memcpy(out + 1, &len, 4);
        memcpy(out + 5, &crc, 4);

        if (!write_full(fd, out, sizeof(out), timeout_ms) ||
            !write_full(fd, block, 1, timeout_ms) ||
            !read_full(fd, header, sizeof(header), timeout_ms)) {
            goto done;
        }
    }

    if (header[0] != 1) goto done;
    memcpy(&block_len, header + 1, 4); block_len = ntohl(block_len);
    memcpy(&sent_crc, header + 5, 4); sent_crc = ntohl(sent_crc);

    if (block_len < 9 || block_len > MAX_BLOCK) goto done;
    response = malloc(block_len);
    if (!response || !read_full(fd, response, block_len, timeout_ms)) goto done;

    actual_crc = radmin_crc(response, block_len);
    if (actual_crc != sent_crc || response[0] != 0x08) goto done;

    {
        uint32_t flags = le32(response + 1);
        const char *v = NULL;

        switch (flags & 0x0A000003U) {
        case 0x08000000U:
        case 0x08000001U:
            switch (flags & 0x00080001U) {
            case 0: v = "2.0"; break;
            case 0x00080001U: v = "2.1"; break;
            case 1: v = "2.2"; break;
            }
            break;
        case 0x0A000002U:
            v = "3";
            break;
        default:
            break;
        }

        snprintf(version, version_len, "%s", v ? v : "unknown");
        result = 1;
    }

done:
    free(response);
    close(fd);
    return result;
}

static void record_target(const struct job *j, const char *ip, const char *version) {
    char dir[1024], file[1200];
    FILE *fp;

    if (mkdir_output(j->output, version, dir, sizeof(dir)) < 0) return;
    if (snprintf(file, sizeof(file), "%s/%d.txt", dir, j->port) >= (int)sizeof(file)) return;

    fp = fopen(file, "a");
    if (!fp) return;
    fprintf(fp, "%s\n", ip);
    fclose(fp);
}

static void print_progress_locked(const struct job *j) {
    size_t checked = j->g ? j->g->checked : j->completed;
    size_t found = j->g ? j->g->found : j->found;
    size_t total = j->g ? j->g->total : j->count;
    size_t remaining = total > checked ? total - checked : 0;
    const struct timespec *start = j->g ? &j->g->started : &j->started;
    double elapsed = elapsed_seconds(start);
    double rate = elapsed > 0.0 ? (double)checked / elapsed : 0.0;
    double eta = rate > 0.0 && remaining > 0 ? (double)remaining / rate : -1.0;
    char eta_text[32];

    format_eta(eta, eta_text, sizeof(eta_text));
    printf("\033[2K\r[overall] checked=%zu/%zu (%.2f%%) | remaining=%zu (%.2f%%) | rate=%.1f/s | ETA=%s | found=%zu",
           checked,
           total,
           total ? 100.0 * (double)checked / (double)total : 100.0,
           remaining,
           total ? 100.0 * (double)remaining / (double)total : 0.0,
           rate,
           eta_text,
           found);
    fflush(stdout);
}

static void *worker(void *arg) {
    struct job *j = arg;

    for (;;) {
        size_t index;
        char version[16];
        int found;

        pthread_mutex_lock(&j->lock);
        if (j->next >= j->count) {
            pthread_mutex_unlock(&j->lock);
            break;
        }
        index = j->next++;
        pthread_mutex_unlock(&j->lock);

        found = probe(j->targets[index].ip, j->port, j->timeout_ms, version, sizeof(version));

        pthread_mutex_lock(&j->lock);
        j->completed++;

        if (j->g) {
            pthread_mutex_lock(&j->g->lock);
            j->g->checked++;
            if (found) j->g->found++;
            pthread_mutex_unlock(&j->g->lock);
        }

        if (found) {
            record_target(j, j->targets[index].ip, version);
            j->found++;
        }

        print_progress_locked(j);
        pthread_mutex_unlock(&j->lock);
    }
    return NULL;
}

static int port_cmp(const void *a, const void *b) {
    const struct port_file *x = a;
    const struct port_file *y = b;
    return (x->port < y->port) ? -1 : ((x->port > y->port) ? 1 : 0);
}

static int collect_port_files(const char *dir, struct port_file **out, size_t *count) {
    DIR *dp = opendir(dir);
    struct dirent *ent;
    struct port_file *items = NULL;
    size_t n = 0, cap = 0;

    if (!dp) return -1;

    while ((ent = readdir(dp)) != NULL) {
        size_t len;
        char *end;
        long port_num;
        struct stat st;
        char path[1024];

        if (ent->d_name[0] == '.') continue;
        len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 4, ".txt") != 0) continue;

        port_num = strtol(ent->d_name, &end, 10);
        if (end != ent->d_name + len - 4 || port_num < 1 || port_num > 65535) continue;

        if (snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) >= (int)sizeof(path)) continue;
        if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) continue;

        if (n == cap) {
            struct port_file *tmp;
            cap = cap ? cap * 2 : 16;
            tmp = realloc(items, cap * sizeof(*items));
            if (!tmp) {
                free(items);
                closedir(dp);
                return -1;
            }
            items = tmp;
        }

        snprintf(items[n].name, sizeof(items[n].name), "%s", ent->d_name);
        items[n].port = (int)port_num;
        n++;
    }

    closedir(dp);
    qsort(items, n, sizeof(*items), port_cmp);
    *out = items;
    *count = n;
    return 0;
}

static int count_valid_targets(const char *path, size_t *count_out) {
    FILE *fp = fopen(path, "r");
    char line[MAX_LINE];
    size_t count = 0;

    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        size_t n;

        while (*p == ' ' || *p == '\t') ++p;
        n = strcspn(p, " \t\r\n#");
        p[n] = 0;
        if (!*p) continue;

        {
            struct in_addr a;
            if (inet_pton(AF_INET, p, &a) != 1) continue;
        }
        count++;
    }

    fclose(fp);
    *count_out = count;
    return 0;
}

static int scan_file(const char *dir, const struct port_file *pf, const char *output,
                     int threads, int timeout_ms, struct global_stats *g) {
    char path[1024], line[MAX_LINE];
    FILE *fp;
    struct target *targets = NULL;
    size_t count = 0, cap = 0;
    struct job job;
    pthread_t *ids = NULL;
    pthread_attr_t attr;
    int created = 0;
    int rc = 0;

    if (snprintf(path, sizeof(path), "%s/%s", dir, pf->name) >= (int)sizeof(path)) {
        fprintf(stderr, "path too long: %s/%s\n", dir, pf->name);
        return 1;
    }

    fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return 1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        size_t n;

        while (*p == ' ' || *p == '\t') ++p;
        n = strcspn(p, " \t\r\n#");
        p[n] = 0;
        if (!*p) continue;

        {
            struct in_addr a;
            if (inet_pton(AF_INET, p, &a) != 1) continue;
        }

        if (count == cap) {
            struct target *tmp;
            cap = cap ? cap * 2 : 256;
            tmp = realloc(targets, cap * sizeof(*targets));
            if (!tmp) {
                fclose(fp);
                free(targets);
                return 1;
            }
            targets = tmp;
        }

        snprintf(targets[count].ip, sizeof(targets[count].ip), "%s", p);
        count++;
    }
    fclose(fp);

    if (!count) {
        free(targets);
        return 0;
    }

    memset(&job, 0, sizeof(job));
    job.targets = targets;
    job.count = count;
    job.next = 0;
    job.port = pf->port;
    job.timeout_ms = timeout_ms;
    job.output = output;
    job.g = g;
    clock_gettime(CLOCK_MONOTONIC, &job.started);
    pthread_mutex_init(&job.lock, NULL);

    ids = calloc((size_t)threads, sizeof(*ids));
    if (!ids) {
        perror("calloc");
        pthread_mutex_destroy(&job.lock);
        free(targets);
        return 1;
    }

    pthread_attr_init(&attr);
    if (pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE) != 0) {
        fprintf(stderr, "warning: could not set thread stack size\n");
    }

    for (int i = 0; i < threads; ++i) {
        int err = pthread_create(&ids[created], &attr, worker, &job);
        if (err != 0) {
            fprintf(stderr, "\npthread_create failed at %d/%d: %s\n", i + 1, threads, strerror(err));
            break;
        }
        created++;
    }

    pthread_attr_destroy(&attr);
    for (int i = 0; i < created; ++i) {
        pthread_join(ids[i], NULL);
    }

    pthread_mutex_destroy(&job.lock);
    free(ids);
    free(targets);

    if (created == 0) rc = 1;
    return rc;
}

int main(int argc, char **argv) {
    const char *input = NULL, *output = "./results";
    int threads = DEFAULT_THREADS, timeout = DEFAULT_TIMEOUT_MS, opt;
    struct port_file *files = NULL;
    size_t file_count = 0;
    size_t total_targets = 0;
    global_stats g;
    int rc = 0;

    signal(SIGPIPE, SIG_IGN);

    while ((opt = getopt(argc, argv, "i:o:t:w:h")) != -1) {
        switch (opt) {
        case 'i': input = optarg; break;
        case 'o': output = optarg; break;
        case 't': threads = atoi(optarg); break;
        case 'w': timeout = atoi(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 2;
        }
    }

    if (!input || threads < 1 || timeout < 100) {
        usage(argv[0]);
        return 2;
    }

    {
        struct stat st;
        if (stat(input, &st) < 0 || !S_ISDIR(st.st_mode)) {
            fprintf(stderr, "-i must be a directory: %s\n", input);
            return 2;
        }
    }

    if (collect_port_files(input, &files, &file_count) < 0) {
        perror(input);
        return 1;
    }
    if (file_count == 0) {
        fprintf(stderr, "No valid port-named .txt files found in %s\n", input);
        free(files);
        return 1;
    }

    for (size_t i = 0; i < file_count; ++i) {
        char path[1024];
        size_t c = 0;
        if (snprintf(path, sizeof(path), "%s/%s", input, files[i].name) >= (int)sizeof(path)) continue;
        if (count_valid_targets(path, &c) == 0) total_targets += c;
    }

    memset(&g, 0, sizeof(g));
    clock_gettime(CLOCK_MONOTONIC, &g.started);
    g.total = total_targets;
    pthread_mutex_init(&g.lock, NULL);

    printf("[start] directory=%s | files=%zu | total_targets=%zu | requested_threads=%d\n",
           input, file_count, total_targets, threads);

    for (size_t i = 0; i < file_count; ++i) {
        if (scan_file(input, &files[i], output, threads, timeout, &g) != 0) {
            rc = 1;
        }
    }

    printf("\n[complete] files=%zu/%zu | checked=%zu/%zu | found=%zu | elapsed=%.1fs\n",
           file_count, file_count, g.checked, g.total, g.found, elapsed_seconds(&g.started));
    fflush(stdout);

    pthread_mutex_destroy(&g.lock);
    free(files);
    return rc;
}
