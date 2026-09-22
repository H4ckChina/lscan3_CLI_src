#!/usr/bin/env python3
from pathlib import Path
import re

p = Path(__file__).with_name('radmin_probe.c')
s = p.read_text()

# Extend the job with shared overall-progress counters.
s = s.replace(
'''    struct timespec started; pthread_mutex_t lock;\n};''',
'''    struct timespec started;\n    size_t *overall_completed;\n    size_t *overall_found;\n    size_t overall_total;\n    struct timespec *overall_started;\n    pthread_mutex_t lock;\n};''', 1)

# Replace per-file-only progress printer with a single global progress line.
start = s.index('static void print_progress_locked(')
end = s.index('\nstatic void *worker(', start)
new_progress = r'''static void print_progress_locked(const struct job *j) {
    size_t checked = j->overall_completed ? *j->overall_completed : j->completed;
    size_t found = j->overall_found ? *j->overall_found : j->found;
    size_t total = j->overall_total ? j->overall_total : j->count;
    size_t remaining = total > checked ? total - checked : 0;
    const struct timespec *started = j->overall_started ? j->overall_started : &j->started;
    double elapsed = elapsed_seconds(started);
    double rate = elapsed > 0.0 ? (double)checked / elapsed : 0.0;
    double eta = rate > 0.0 && remaining > 0 ? (double)remaining / rate : -1.0;
    char eta_text[32];

    format_eta(eta, eta_text, sizeof(eta_text));
    printf("\\033[2K\\r[overall] checked=%zu/%zu (%.2f%%) | remaining=%zu (%.2f%%) | rate=%.1f/s | ETA=%s | found=%zu",
           checked, total, total ? 100.0 * (double)checked / (double)total : 100.0,
           remaining, total ? 100.0 * (double)remaining / (double)total : 0.0,
           rate, eta_text, found);
    fflush(stdout);
}
'''
s = s[:start] + new_progress + s[end:]

# Replace worker so counters and the one terminal line are updated for every target.
start = s.index('static void *worker(')
end = s.index('\nstatic int port_cmp(', start)
new_worker = r'''static void *worker(void *arg) {
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
        if (found) {
            record_target(j, j->targets[index].ip, version);
            j->found++;
        }
        if (j->overall_completed) (*j->overall_completed)++;
        if (found && j->overall_found) (*j->overall_found)++;
        print_progress_locked(j);
        pthread_mutex_unlock(&j->lock);
    }
    return NULL;
}
'''
s = s[:start] + new_worker + s[end:]

# Add shared-progress parameters to scan_file.
s = s.replace(
'''static int scan_file(const char *dir, const struct port_file *pf, const char *output, int threads, int timeout_ms) {''',
'''static int scan_file(const char *dir, const struct port_file *pf, const char *output,
                     int threads, int timeout_ms, size_t *overall_completed,
                     size_t *overall_found, size_t overall_total,
                     struct timespec *overall_started) {''', 1)

# Initialize the shared fields and remove per-file progress/header output.
s = s.replace(
'''    job.output = output;\n    pthread_mutex_init(&job.lock, NULL);''',
'''    job.output = output;\n    job.overall_completed = overall_completed;\n    job.overall_found = overall_found;\n    job.overall_total = overall_total;\n    job.overall_started = overall_started;\n    pthread_mutex_init(&job.lock, NULL);''', 1)
s = re.sub(r'''\n    printf\("\\n\\[file\].*?threads=%d\\n",\n           pf->port, pf->name, count, threads\);\n    pthread_mutex_lock\(&job\.lock\);\n    print_progress_locked\(&job\);\n    pthread_mutex_unlock\(&job\.lock\);\n''', '\n', s, count=1, flags=re.S)

# Main's old per-file overall print is removed; pass shared counters into scan_file.
s = re.sub(r'''\n        double elapsed = elapsed_seconds\(&overall_started\);.*?\n        fflush\(stdout\);\n\n        port_rc = scan_file\(input, &files\[i\], output, threads, timeout\);''',
'''\n        port_rc = scan_file(input, &files[i], output, threads, timeout,\n                            &done_targets, &found_total, total_targets,\n                            &overall_started);''', s, count=1, flags=re.S)

# Remove the dead post-scan dummy blocks and the duplicate done_targets recalculation.
s = re.sub(r'''\n        /\* Recompute progress after this file.*?\n        \}\n\n        \{\n            char version_dir.*?\n        \}\n\n        /\* file-level result tracking.*?\n        \{\n            char buf.*?\n        \}\n''', '\n', s, count=1, flags=re.S)

p.write_text(s)
print('patched', p)
PY
