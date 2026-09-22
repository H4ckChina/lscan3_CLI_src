#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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
#define DEFAULT_PORT 4899
#define DEFAULT_TIMEOUT_MS 3000
#define DEFAULT_THREADS 4
#define THREAD_STACK_SIZE (256U * 1024U)

struct target { char ip[INET_ADDRSTRLEN]; };
struct job {
    struct target *targets; size_t count, next, completed, found;
    int port, timeout_ms; const char *output;
    struct timespec started; pthread_mutex_t lock;
};

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s -i targets.txt [-p port] [-o dir] [-t threads] [-w timeout_ms]\n", name);
    fprintf(stderr, "  -t accepts any positive value; the OS may limit the actual number created\n");
}

static double elapsed_seconds(const struct timespec *start) {
    struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) +
           (double)(now.tv_nsec - start->tv_nsec) / 1000000000.0;
}

static void format_eta(double seconds, char *out, size_t size) {
    unsigned long total;
    if (seconds < 0 || seconds > 864000000.0) { snprintf(out, size, "unknown"); return; }
    total = (unsigned long)(seconds + 0.5);
    snprintf(out, size, "%02lu:%02lu:%02lu", total / 3600, (total / 60) % 60, total % 60);
}

static int mkdir_one(const char *path) { return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1; }
static int mkdir_output(const char *base, const char *version, char *dir, size_t n) {
    if (mkdir_one(base) < 0 || snprintf(dir, n, "%s/%s", base, version) >= (int)n) return -1;
    return mkdir_one(dir);
}

static int wait_fd(int fd, int writing, int timeout_ms) {
    struct pollfd p = { .fd = fd, .events = writing ? POLLOUT : POLLIN, .revents = 0 };
    for (;;) {
        int rc = poll(&p, 1, timeout_ms);
        if (rc > 0) return !(p.revents & (POLLERR | POLLHUP | POLLNVAL)) && (p.revents & p.events);
        if (rc == 0) return 0;
        if (errno != EINTR) return 0;
    }
}

static int read_full(int fd, void *buf, size_t len, int timeout_ms) {
    size_t done = 0;
    while (done < len) {
        ssize_t n; if (!wait_fd(fd, 0, timeout_ms)) return 0;
        n = recv(fd, (char *)buf + done, len - done, 0);
        if (n <= 0) return 0; done += (size_t)n;
    }
    return 1;
}
static int write_full(int fd, const void *buf, size_t len, int timeout_ms) {
    size_t done = 0;
    while (done < len) {
        ssize_t n; if (!wait_fd(fd, 1, timeout_ms)) return 0;
        n = send(fd, (const char *)buf + done, len - done, MSG_NOSIGNAL);
        if (n <= 0) return 0; done += (size_t)n;
    }
    return 1;
}
static uint32_t le32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint32_t radmin_crc(const unsigned char *p, size_t len) {
    uint32_t sum = 0;
    while (len) {
        size_t take = len < 4 ? len : 4; uint32_t word = 0;
        for (size_t i = 0; i < take; ++i) word |= (uint32_t)p[i] << (8 * i);
        sum += word; p += take; len -= take;
    }
    return sum;
}

static int connect_target(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0), flags, rc; struct sockaddr_in sa;
    if (fd < 0) return -1;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        int error = 0; socklen_t len = sizeof(error);
        if (!wait_fd(fd, 1, timeout_ms) || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) { close(fd); return -1; }
    }
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    return fd;
}

/* Non-authenticating Radmin version probe. */
static int probe(const char *ip, int port, int timeout_ms, char *version, size_t version_len) {
    unsigned char header[9], block[1] = { 0x08 }, *response = NULL;
    uint32_t block_len, sent_crc, actual_crc; int fd = connect_target(ip, port, timeout_ms), result = 0;
    if (fd < 0) return 0;
    {
        unsigned char out[9]; uint32_t len = htonl(1), crc = htonl(radmin_crc(block, 1));
        out[0] = 1; memcpy(out + 1, &len, 4); memcpy(out + 5, &crc, 4);
        if (!write_full(fd, out, sizeof(out), timeout_ms) || !write_full(fd, block, 1, timeout_ms) || !read_full(fd, header, sizeof(header), timeout_ms)) goto done;
    }
    if (header[0] != 1) goto done;
    memcpy(&block_len, header + 1, 4); block_len = ntohl(block_len);
    memcpy(&sent_crc, header + 5, 4); sent_crc = ntohl(sent_crc);
    if (block_len < 9 || block_len > MAX_BLOCK || !(response = malloc(block_len)) || !read_full(fd, response, block_len, timeout_ms)) goto done;
    actual_crc = radmin_crc(response, block_len);
    if (actual_crc != sent_crc || response[0] != 0x08) goto done;
    {
        uint32_t flags = le32(response + 1); const char *v = NULL;
        switch (flags & 0x0A000003U) {
        case 0x08000000U: case 0x08000001U:
            switch (flags & 0x00080001U) { case 0: v = "2.0"; break; case 0x00080001U: v = "2.1"; break; case 1: v = "2.2"; break; }
            break;
        case 0x0A000002U: v = "3"; break;
        }
        snprintf(version, version_len, "%s", v ? v : "unknown"); result = 1;
    }
done: free(response); close(fd); return result;
}

static void record_target(const struct job *j, const char *ip, const char *version) {
    char dir[1024], file[1200]; FILE *fp;
    if (mkdir_output(j->output, version, dir, sizeof(dir)) < 0 || snprintf(file, sizeof(file), "%s/%d.txt", dir, j->port) >= (int)sizeof(file)) return;
    if ((fp = fopen(file, "a"))) { fprintf(fp, "%s\n", ip); fclose(fp); }
}

static void print_progress_locked(const struct job *j) {
    size_t remaining = j->count - j->completed; double elapsed = elapsed_seconds(&j->started);
    double rate = elapsed > 0.0 ? (double)j->completed / elapsed : 0.0;
    double eta = rate > 0.0 ? (double)remaining / rate : -1.0; char eta_text[32];
    format_eta(eta, eta_text, sizeof(eta_text));
    printf("\r[progress] checked: %zu/%zu (%.2f%%) | remaining: %zu (%.2f%%) | rate: %.1f/s | ETA: %s | found: %zu",
           j->completed, j->count, j->count ? 100.0 * j->completed / j->count : 100.0,
           remaining, j->count ? 100.0 * remaining / j->count : 0.0, rate, eta_text, j->found);
    fflush(stdout);
}

static void *worker(void *arg) {
    struct job *j = arg;
    for (;;) {
        size_t index; char version[16]; int found;
        pthread_mutex_lock(&j->lock);
        if (j->next >= j->count) { pthread_mutex_unlock(&j->lock); break; }
        index = j->next++; pthread_mutex_unlock(&j->lock);
        found = probe(j->targets[index].ip, j->port, j->timeout_ms, version, sizeof(version));
        pthread_mutex_lock(&j->lock); j->completed++;
        if (found) { record_target(j, j->targets[index].ip, version); j->found++; printf("\n[found] %s:%d -> Radmin %s\n", j->targets[index].ip, j->port, version); }
        print_progress_locked(j); pthread_mutex_unlock(&j->lock);
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *input = NULL, *output = "./results"; int port = DEFAULT_PORT, timeout = DEFAULT_TIMEOUT_MS, threads = DEFAULT_THREADS, opt, created = 0;
    struct target *targets = NULL; size_t count = 0, cap = 0; FILE *fp; char line[MAX_LINE]; pthread_t *ids; pthread_attr_t attr; struct job job;
    signal(SIGPIPE, SIG_IGN);
    while ((opt = getopt(argc, argv, "i:p:o:t:w:h")) != -1) {
        switch (opt) { case 'i': input = optarg; break; case 'p': port = atoi(optarg); break; case 'o': output = optarg; break; case 't': threads = atoi(optarg); break; case 'w': timeout = atoi(optarg); break; default: usage(argv[0]); return opt == 'h' ? 0 : 2; }
    }
    if (!input || port < 1 || port > 65535 || threads < 1 || timeout < 100) { usage(argv[0]); return 2; }
    if (!(fp = fopen(input, "r"))) { perror(input); return 1; }
    while (fgets(line, sizeof(line), fp)) {
        char *p = line; size_t n; while (*p == ' ' || *p == '\t') ++p; n = strcspn(p, " \t\r\n#"); p[n] = 0; if (!*p) continue;
        { struct in_addr a; if (inet_pton(AF_INET, p, &a) != 1) continue; }
        if (count == cap) { struct target *tmp; cap = cap ? cap * 2 : 256; if (!(tmp = realloc(targets, cap * sizeof(*targets)))) { fclose(fp); free(targets); return 1; } targets = tmp; }
        snprintf(targets[count++].ip, sizeof(targets[count].ip), "%s", p);
    }
    fclose(fp); if (!count) { fprintf(stderr, "No valid IPv4 targets.\n"); free(targets); return 1; }
    memset(&job, 0, sizeof(job)); job.targets = targets; job.count = count; job.port = port; job.timeout_ms = timeout; job.output = output; pthread_mutex_init(&job.lock, NULL); clock_gettime(CLOCK_MONOTONIC, &job.started);
    printf("[start] targets: %zu | requested threads: %d | port: %d\n", count, threads, port); pthread_mutex_lock(&job.lock); print_progress_locked(&job); pthread_mutex_unlock(&job.lock);
    ids = calloc((size_t)threads, sizeof(*ids)); if (!ids) { perror("calloc"); pthread_mutex_destroy(&job.lock); free(targets); return 1; }
    pthread_attr_init(&attr); pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    for (int i = 0; i < threads; ++i) { int rc = pthread_create(&ids[created], &attr, worker, &job); if (rc) { fprintf(stderr, "\npthread_create failed at %d/%d: %s\n", i + 1, threads, strerror(rc)); break; } created++; }
    pthread_attr_destroy(&attr); for (int i = 0; i < created; ++i) pthread_join(ids[i], NULL);
    printf("\n"); fprintf(stderr, "Scan complete: %zu checked, %zu remaining, %zu Radmin services found, elapsed %.1fs.\n", job.completed, job.count - job.completed, job.found, elapsed_seconds(&job.started));
    pthread_mutex_destroy(&job.lock); free(ids); free(targets); return created ? 0 : 1;
}
