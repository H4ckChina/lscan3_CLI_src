#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_BLOCK 1048576U
#define MAX_LINE 256
#define DEFAULT_PORT 4899
#define DEFAULT_TIMEOUT_MS 3000
#define DEFAULT_THREADS 4

struct target { char ip[INET_ADDRSTRLEN]; };
struct job {
    struct target *targets;
    size_t count;
    size_t next;
    int port;
    int timeout_ms;
    const char *output;
    pthread_mutex_t lock;
};

static void usage(const char *name) {
    fprintf(stderr, "Usage: %s -i targets.txt [-p port] [-o dir] [-t threads] [-w timeout_ms]\n", name);
}

static int mkdir_one(const char *path) {
    if (mkdir(path, 0755) == 0 || errno == EEXIST) return 0;
    return -1;
}

static int mkdir_output(const char *base, const char *version, char *dir, size_t n) {
    if (mkdir_one(base) < 0) return -1;
    if (snprintf(dir, n, "%s/%s", base, version) >= (int)n) return -1;
    return mkdir_one(dir);
}

static int wait_fd(int fd, int writing, int timeout_ms) {
    fd_set set;
    struct timeval tv;
    FD_ZERO(&set); FD_SET(fd, &set);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return select(fd + 1, writing ? NULL : &set, writing ? &set : NULL, NULL, &tv) > 0;
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
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Matches the checksum used by the original Radmin packet implementation. */
static uint32_t radmin_crc(const unsigned char *p, size_t len) {
    uint32_t sum = 0;
    while (len) {
        size_t take = len < 4 ? len : 4;
        uint32_t word = 0;
        for (size_t i = 0; i < take; ++i) word |= (uint32_t)p[i] << (8 * i);
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
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { close(fd); return -1; }
    memset(&sa, 0, sizeof(sa)); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) { close(fd); return -1; }
    rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { close(fd); return -1; }
    if (rc < 0) {
        int error = 0; socklen_t elen = sizeof(error);
        if (!wait_fd(fd, 1, timeout_ms) || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &elen) < 0 || error) {
            close(fd); return -1;
        }
    }
    if (fcntl(fd, F_SETFL, flags) < 0) { close(fd); return -1; }
    return fd;
}

/* Returns 1 for a confirmed Radmin response, 0 otherwise. */
static int probe(const char *ip, int port, int timeout_ms, char *version, size_t version_len) {
    unsigned char request[5] = { 0x01, 0, 0, 0, 0 };
    unsigned char header[9], *block = NULL;
    int fd = connect_target(ip, port, timeout_ms);
    uint32_t block_len, sent_crc, actual_crc;
    int result = 0;
    if (fd < 0) return 0;
    /* Header: marker=1, network-order block length, network-order checksum. */
    { uint32_t len = htonl(5), crc = htonl(radmin_crc(request + 0, 5));
      memcpy(request + 1, &len, 4); /* overwritten below with the actual packet */
      (void)crc;
    }
    /* The request block is code 0x08 with zero data. */
    { unsigned char out_header[9]; uint32_t len = htonl(5), crc;
      unsigned char block_out[5] = { 0x08, 0, 0, 0, 0 };
      crc = htonl(radmin_crc(block_out, 5));
      out_header[0] = 1; memcpy(out_header + 1, &len, 4); memcpy(out_header + 5, &crc, 4);
      if (!write_full(fd, out_header, sizeof(out_header), timeout_ms) ||
          !write_full(fd, block_out, sizeof(block_out), timeout_ms) ||
          !read_full(fd, header, sizeof(header), timeout_ms)) goto done;
    }
    if (header[0] != 1) goto done;
    memcpy(&block_len, header + 1, 4); block_len = ntohl(block_len);
    memcpy(&sent_crc, header + 5, 4); sent_crc = ntohl(sent_crc);
    if (block_len < 5 || block_len > MAX_BLOCK) goto done;
    block = malloc(block_len);
    if (!block || !read_full(fd, block, block_len, timeout_ms)) goto done;
    actual_crc = radmin_crc(block, block_len);
    if (actual_crc != sent_crc || block[0] != 0x08 || block_len < 9) goto done;
    {
        uint32_t flags = le32(block + 1);
        const char *v = NULL;
        switch (flags & 0x0A000003U) {
        case 0x08000000U: case 0x08000001U:
            switch (flags & 0x00080001U) {
            case 0: v = "2.0"; break; case 0x00080001U: v = "2.1"; break; case 1: v = "2.2"; break;
            }
            break;
        case 0x0A000002U: v = "3"; break;
        }
        snprintf(version, version_len, "%s", v ? v : "unknown");
        result = 1;
    }
done:
    free(block); close(fd); return result;
}

static void record_target(const struct job *j, const char *ip, const char *version) {
    char dir[1024], file[1200]; FILE *fp;
    if (mkdir_output(j->output, version, dir, sizeof(dir)) < 0) return;
    if (snprintf(file, sizeof(file), "%s/%d.txt", dir, j->port) >= (int)sizeof(file)) return;
    fp = fopen(file, "a");
    if (!fp) return;
    fprintf(fp, "%s\n", ip); fclose(fp);
}

static void *worker(void *arg) {
    struct job *j = arg;
    for (;;) {
        size_t index; char version[16];
        pthread_mutex_lock(&j->lock);
        if (j->next >= j->count) { pthread_mutex_unlock(&j->lock); break; }
        index = j->next++;
        pthread_mutex_unlock(&j->lock);
        if (probe(j->targets[index].ip, j->port, j->timeout_ms, version, sizeof(version))) {
            pthread_mutex_lock(&j->lock);
            record_target(j, j->targets[index].ip, version);
            pthread_mutex_unlock(&j->lock);
            printf("%s:%d -> Radmin %s\n", j->targets[index].ip, j->port, version);
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    const char *input = NULL, *output = "./results";
    int port = DEFAULT_PORT, timeout = DEFAULT_TIMEOUT_MS, threads = DEFAULT_THREADS, opt;
    struct target *targets = NULL; size_t count = 0, cap = 0; FILE *fp; char line[MAX_LINE];
    pthread_t *ids; struct job job;
    signal(SIGPIPE, SIG_IGN);
    while ((opt = getopt(argc, argv, "i:p:o:t:w:h")) != -1) {
        switch (opt) {
        case 'i': input = optarg; break; case 'p': port = atoi(optarg); break;
        case 'o': output = optarg; break; case 't': threads = atoi(optarg); break;
        case 'w': timeout = atoi(optarg); break; default: usage(argv[0]); return opt == 'h' ? 0 : 2;
        }
    }
    if (!input || port < 1 || port > 65535 || threads < 1 || threads > 128 || timeout < 100) { usage(argv[0]); return 2; }
    fp = fopen(input, "r"); if (!fp) { perror(input); return 1; }
    while (fgets(line, sizeof(line), fp)) {
        char *p = line; size_t n;
        while (*p == ' ' || *p == '\t') ++p;
        n = strcspn(p, " \t\r\n#"); p[n] = 0;
        if (!*p) continue;
        { struct in_addr a; if (inet_pton(AF_INET, p, &a) != 1) continue; }
        if (count == cap) { cap = cap ? cap * 2 : 256; targets = realloc(targets, cap * sizeof(*targets)); if (!targets) return 1; }
        snprintf(targets[count++].ip, sizeof(targets[count].ip), "%s", p);
    }
    fclose(fp); if (!count) { fprintf(stderr, "No valid IPv4 targets.\n"); free(targets); return 1; }
    memset(&job, 0, sizeof(job)); job.targets = targets; job.count = count; job.port = port; job.timeout_ms = timeout; job.output = output; pthread_mutex_init(&job.lock, NULL);
    ids = calloc((size_t)threads, sizeof(*ids)); if (!ids) return 1;
    for (int i = 0; i < threads; ++i) pthread_create(&ids[i], NULL, worker, &job);
    for (int i = 0; i < threads; ++i) pthread_join(ids[i], NULL);
    pthread_mutex_destroy(&job.lock); free(ids); free(targets); return 0;
}
