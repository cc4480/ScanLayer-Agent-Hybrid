/*
 * qnx-runner — on-target node runtime for the QNX agent.
 *
 * One job: run(argv[], timeout_ms) -> {exit, signal, stdout, stderr,
 * truncated, duration_ms}. argv array only, never a shell. Portable POSIX C:
 * builds with `qcc -Vgcc_ntox86_64` for QNX 8.0 and with gcc/cc on Linux
 * (the stand-in target used before the SDP lands).
 *
 * Protocol: line-delimited JSON. One request line in, one response line out.
 *   request : {"token":"...","argv":["/bin/ls","-l"],"timeout_ms":100000}
 *   response: {"ok":true,"exit":0,"signal":0,"stdout":"...","stderr":"...",
 *              "truncated":false,"timed_out":false,"duration_ms":12}
 *   error   : {"ok":false,"error":"<code>","detail":"..."}
 *
 * Modes:
 *   qnx-runner --stdio  [--allow-file F]                 one request on stdin
 *   qnx-runner --listen PORT --token-file F [--bind ADDR] [--allow-file F]
 *              [--spawn-log F]
 *
 * Defense in depth: the gateway's scope gate decides first. The runner then
 * re-checks on its own: argv[0] must be an absolute path, and with
 * --allow-file it must appear (exact line) in that allowlist. A request the
 * runner refuses is never spawned. --spawn-log appends one line per actual
 * spawn, so "denied pre-spawn" is provable from the target side.
 */
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define OUT_CAP 40000          /* chars per stream, Parrot value */
#define DEFAULT_TIMEOUT 100000 /* ms, Parrot value */
#define MAX_TIMEOUT 300000
#define MAX_REQ 65536
#define MAX_ARGS 256
#define CHILD_PATH "PATH=/proc/boot:/system/bin:/system/xbin:/bin:/usr/bin:/sbin:/usr/sbin"

static const char *g_token = NULL;
static const char *g_allow_file = NULL;
static const char *g_spawn_log = NULL;

/* ---------- output buffer ---------- */
typedef struct { char *p; size_t n, cap; } buf_t;

static void buf_put(buf_t *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->n + n + 1) nc *= 2;
        char *q = realloc(b->p, nc);
        if (!q) { perror("realloc"); exit(70); }
        b->p = q; b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static void buf_str(buf_t *b, const char *s) { buf_put(b, s, strlen(s)); }
static void buf_fmt(buf_t *b, const char *fmt, ...) {
    char tmp[256]; va_list ap; va_start(ap, fmt);
    int k = vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
    if (k > 0) buf_put(b, tmp, (size_t)k < sizeof tmp ? (size_t)k : sizeof tmp - 1);
}

/* JSON-escape bytes; invalid UTF-8 bytes become U+FFFD so output is always valid JSON. */
static void buf_json_str(buf_t *b, const unsigned char *s, size_t n) {
    buf_str(b, "\"");
    size_t i = 0;
    while (i < n) {
        unsigned char c = s[i];
        if (c == '"') { buf_str(b, "\\\""); i++; }
        else if (c == '\\') { buf_str(b, "\\\\"); i++; }
        else if (c == '\n') { buf_str(b, "\\n"); i++; }
        else if (c == '\r') { buf_str(b, "\\r"); i++; }
        else if (c == '\t') { buf_str(b, "\\t"); i++; }
        else if (c < 0x20 || c == 0x7f) { buf_fmt(b, "\\u%04x", c); i++; }
        else if (c < 0x80) { buf_put(b, (const char *)&s[i], 1); i++; }
        else {
            int len = (c >= 0xf0 && c <= 0xf4) ? 4 : (c >= 0xe0) ? 3 : (c >= 0xc2 && c <= 0xdf) ? 2 : 0;
            int ok = len > 0 && i + (size_t)len <= n;
            for (int k = 1; ok && k < len; k++) if ((s[i + k] & 0xc0) != 0x80) ok = 0;
            if (ok) { buf_put(b, (const char *)&s[i], (size_t)len); i += (size_t)len; }
            else { buf_str(b, "\\ufffd"); i++; }
        }
    }
    buf_str(b, "\"");
}

static void reply_error(int fd, const char *code, const char *detail) {
    buf_t b = {0};
    buf_str(&b, "{\"ok\":false,\"error\":");
    buf_json_str(&b, (const unsigned char *)code, strlen(code));
    buf_str(&b, ",\"detail\":");
    buf_json_str(&b, (const unsigned char *)detail, strlen(detail));
    buf_str(&b, "}\n");
    (void)!write(fd, b.p, b.n);
    free(b.p);
}

/* ---------- minimal JSON request parser ---------- */
typedef struct {
    char *token;
    char *argv[MAX_ARGS + 1];
    int argc;
    long timeout_ms;
    int has_argv;
} req_t;

static const char *skip_ws(const char *p) { while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++; return p; }

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parse a JSON string at *pp (pointing at the opening quote). Returns malloc'd UTF-8 or NULL. */
static char *parse_string(const char **pp) {
    const char *p = *pp;
    if (*p != '"') return NULL;
    p++;
    buf_t b = {0};
    buf_put(&b, "", 0);
    while (*p && *p != '"') {
        if ((unsigned char)*p < 0x20) { free(b.p); return NULL; }
        if (*p == '\\') {
            p++;
            char e = *p++;
            switch (e) {
            case '"': buf_put(&b, "\"", 1); break;
            case '\\': buf_put(&b, "\\", 1); break;
            case '/': buf_put(&b, "/", 1); break;
            case 'b': buf_put(&b, "\b", 1); break;
            case 'f': buf_put(&b, "\f", 1); break;
            case 'n': buf_put(&b, "\n", 1); break;
            case 'r': buf_put(&b, "\r", 1); break;
            case 't': buf_put(&b, "\t", 1); break;
            case 'u': {
                unsigned cp = 0;
                for (int k = 0; k < 4; k++) { int h = hexval(p[k]); if (h < 0) { free(b.p); return NULL; } cp = cp * 16 + (unsigned)h; }
                p += 4;
                if (cp >= 0xd800 && cp <= 0xdbff && p[0] == '\\' && p[1] == 'u') {
                    unsigned lo = 0;
                    for (int k = 0; k < 4; k++) { int h = hexval(p[2 + k]); if (h < 0) { free(b.p); return NULL; } lo = lo * 16 + (unsigned)h; }
                    if (lo >= 0xdc00 && lo <= 0xdfff) { cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00); p += 6; }
                }
                if (cp == 0) { free(b.p); return NULL; } /* NUL would truncate argv: refuse */
                char u[4]; int n;
                if (cp < 0x80) { u[0] = (char)cp; n = 1; }
                else if (cp < 0x800) { u[0] = (char)(0xc0 | (cp >> 6)); u[1] = (char)(0x80 | (cp & 0x3f)); n = 2; }
                else if (cp < 0x10000) { u[0] = (char)(0xe0 | (cp >> 12)); u[1] = (char)(0x80 | ((cp >> 6) & 0x3f)); u[2] = (char)(0x80 | (cp & 0x3f)); n = 3; }
                else { u[0] = (char)(0xf0 | (cp >> 18)); u[1] = (char)(0x80 | ((cp >> 12) & 0x3f)); u[2] = (char)(0x80 | ((cp >> 6) & 0x3f)); u[3] = (char)(0x80 | (cp & 0x3f)); n = 4; }
                buf_put(&b, u, (size_t)n);
                break;
            }
            default: free(b.p); return NULL;
            }
        } else {
            buf_put(&b, p, 1);
            p++;
        }
    }
    if (*p != '"') { free(b.p); return NULL; }
    *pp = p + 1;
    return b.p;
}

/* Skip any JSON value (for unknown keys). */
static const char *skip_value(const char *p) {
    p = skip_ws(p);
    if (*p == '"') { char *s = parse_string(&p); if (!s) return NULL; free(s); return p; }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p) {
            if (*p == '"') { char *s = parse_string(&p); if (!s) return NULL; free(s); continue; }
            if (*p == '{' || *p == '[') depth++;
            if (*p == '}' || *p == ']') { depth--; if (depth == 0) return p + 1; }
            p++;
        }
        return NULL;
    }
    while (*p && *p != ',' && *p != '}' && *p != ']') p++;
    return p;
}

static void req_free(req_t *r) {
    free(r->token);
    for (int i = 0; i < r->argc; i++) free(r->argv[i]);
}

static int parse_request(const char *line, req_t *r, const char **why) {
    memset(r, 0, sizeof *r);
    r->timeout_ms = DEFAULT_TIMEOUT;
    const char *p = skip_ws(line);
    if (*p != '{') { *why = "request is not a JSON object"; return -1; }
    p = skip_ws(p + 1);
    if (*p == '}') { *why = "empty request"; return -1; }
    for (;;) {
        p = skip_ws(p);
        char *key = parse_string(&p);
        if (!key) { *why = "bad key"; return -1; }
        p = skip_ws(p);
        if (*p != ':') { free(key); *why = "expected ':'"; return -1; }
        p = skip_ws(p + 1);
        if (strcmp(key, "token") == 0) {
            free(r->token);
            r->token = parse_string(&p);
            if (!r->token) { free(key); *why = "token must be a string"; return -1; }
        } else if (strcmp(key, "timeout_ms") == 0) {
            char *end;
            long v = strtol(p, &end, 10);
            if (end == p || v <= 0) { free(key); *why = "timeout_ms must be a positive integer"; return -1; }
            r->timeout_ms = v > MAX_TIMEOUT ? MAX_TIMEOUT : v;
            p = end;
        } else if (strcmp(key, "argv") == 0) {
            if (*p != '[') { free(key); *why = "argv must be an array"; return -1; }
            p = skip_ws(p + 1);
            r->has_argv = 1;
            if (*p == ']') { p++; }
            else for (;;) {
                if (r->argc >= MAX_ARGS) { free(key); *why = "too many args"; return -1; }
                char *a = parse_string(&p);
                if (!a) { free(key); *why = "argv entries must be strings"; return -1; }
                r->argv[r->argc++] = a;
                p = skip_ws(p);
                if (*p == ',') { p = skip_ws(p + 1); continue; }
                if (*p == ']') { p++; break; }
                free(key); *why = "bad argv array"; return -1;
            }
        } else {
            p = skip_value(p);
            if (!p) { free(key); *why = "bad value"; return -1; }
        }
        free(key);
        p = skip_ws(p);
        if (*p == ',') { p++; continue; }
        if (*p == '}') break;
        *why = "expected ',' or '}'";
        return -1;
    }
    r->argv[r->argc] = NULL;
    return 0;
}

/* ---------- policy ---------- */
static int consttime_eq(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    unsigned char d = (unsigned char)(la != lb);
    for (size_t i = 0; i < la; i++) d |= (unsigned char)(a[i] ^ b[i % (lb ? lb : 1)]);
    return d == 0;
}

static int allowlisted(const char *path) {
    if (!g_allow_file) return 1;
    FILE *f = fopen(g_allow_file, "r");
    if (!f) return 0; /* missing allowlist = nothing allowed: fail closed */
    char line[4096];
    int ok = 0;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (n && strcmp(line, path) == 0) { ok = 1; break; }
    }
    fclose(f);
    return ok;
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void log_spawn(char *const argv[]) {
    if (!g_spawn_log) return;
    int fd = open(g_spawn_log, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd < 0) return;
    buf_t b = {0};
    struct timeval tv; gettimeofday(&tv, NULL);
    buf_fmt(&b, "{\"t\":%ld.%03ld,\"pid\":%ld,\"argv\":[", (long)tv.tv_sec, (long)(tv.tv_usec / 1000), (long)getpid());
    for (int i = 0; argv[i]; i++) {
        if (i) buf_str(&b, ",");
        buf_json_str(&b, (const unsigned char *)argv[i], strlen(argv[i]));
    }
    buf_str(&b, "]}\n");
    (void)!write(fd, b.p, b.n);
    close(fd);
    free(b.p);
}

/* ---------- run ---------- */
static void handle(int in_fd, int out_fd) {
    char *line = malloc(MAX_REQ + 1);
    size_t n = 0;
    while (n < MAX_REQ) {
        ssize_t k = read(in_fd, line + n, 1);
        if (k <= 0) break;
        if (line[n] == '\n') break;
        n++;
    }
    line[n] = 0;
    if (n >= MAX_REQ) { reply_error(out_fd, "invalid_argument", "request too large"); free(line); return; }

    req_t r;
    const char *why = "";
    if (parse_request(line, &r, &why) != 0) { reply_error(out_fd, "invalid_argument", why); req_free(&r); free(line); return; }
    free(line);

    if (g_token && (!r.token || !consttime_eq(r.token, g_token))) { reply_error(out_fd, "unauthorized", "bad or missing token"); req_free(&r); return; }
    if (!r.has_argv || r.argc == 0) { reply_error(out_fd, "invalid_argument", "argv is required and non-empty"); req_free(&r); return; }
    if (r.argv[0][0] != '/') { reply_error(out_fd, "denied", "argv[0] must be an absolute path"); req_free(&r); return; }
    if (!allowlisted(r.argv[0])) { reply_error(out_fd, "denied", "argv[0] is not in the runner allowlist"); req_free(&r); return; }

    int po[2], pe[2];
    if (pipe(po) || pipe(pe)) { reply_error(out_fd, "internal", strerror(errno)); req_free(&r); return; }
    long t0 = now_ms();
    pid_t pid = fork();
    if (pid < 0) { reply_error(out_fd, "internal", strerror(errno)); req_free(&r); return; }
    if (pid == 0) {
        setpgid(0, 0);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) { dup2(devnull, 0); close(devnull); }
        dup2(po[1], 1); dup2(pe[1], 2);
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        for (int fd = 3; fd < 256; fd++) close(fd);
        signal(SIGPIPE, SIG_DFL);
        char *envp[] = { CHILD_PATH, "LANG=C", "LC_ALL=C", NULL };
        log_spawn(r.argv);
        execve(r.argv[0], r.argv, envp);
        dprintf(2, "exec failed: %s\n", strerror(errno));
        _exit(127);
    }
    setpgid(pid, pid);
    close(po[1]); close(pe[1]);

    buf_t out = {0}, err = {0};
    buf_put(&out, "", 0); buf_put(&err, "", 0);
    int truncated = 0, timed_out = 0;
    struct pollfd fds[2] = { { po[0], POLLIN, 0 }, { pe[0], POLLIN, 0 } };
    int open_fds = 2;
    long deadline = t0 + r.timeout_ms;
    char chunk[4096];
    while (open_fds > 0) {
        long left = deadline - now_ms();
        if (left <= 0) { timed_out = 1; kill(-pid, SIGKILL); break; }
        int pr = poll(fds, 2, left > 1000 ? 1000 : (int)left);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 2; i++) {
            if (fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t k = read(fds[i].fd, chunk, sizeof chunk);
            if (k <= 0) { close(fds[i].fd); fds[i].fd = -1; open_fds--; continue; }
            buf_t *dst = i == 0 ? &out : &err;
            size_t room = dst->n < OUT_CAP ? OUT_CAP - dst->n : 0;
            if ((size_t)k > room) truncated = 1;
            if (room) buf_put(dst, chunk, (size_t)k < room ? (size_t)k : room);
        }
    }
    for (int i = 0; i < 2; i++) if (fds[i].fd >= 0) close(fds[i].fd);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    long dur = now_ms() - t0;

    buf_t b = {0};
    int ex = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    int sig = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    buf_fmt(&b, "{\"ok\":true,\"exit\":%d,\"signal\":%d,\"stdout\":", ex, sig);
    buf_json_str(&b, (const unsigned char *)out.p, out.n);
    buf_str(&b, ",\"stderr\":");
    buf_json_str(&b, (const unsigned char *)err.p, err.n);
    buf_fmt(&b, ",\"truncated\":%s,\"timed_out\":%s,\"duration_ms\":%ld}\n",
            truncated ? "true" : "false", timed_out ? "true" : "false", dur);
    size_t off = 0;
    while (off < b.n) { ssize_t w = write(out_fd, b.p + off, b.n - off); if (w <= 0) break; off += (size_t)w; }
    free(b.p); free(out.p); free(err.p);
    req_free(&r);
}

static char *read_token_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); exit(66); }
    char tok[512];
    if (!fgets(tok, sizeof tok, f)) { fprintf(stderr, "empty token file\n"); exit(66); }
    fclose(f);
    size_t n = strlen(tok);
    while (n && (tok[n - 1] == '\n' || tok[n - 1] == '\r' || tok[n - 1] == ' ')) tok[--n] = 0;
    if (n < 16) { fprintf(stderr, "token too short (min 16 chars)\n"); exit(66); }
    return strdup(tok);
}

static void usage(void) {
    fprintf(stderr,
        "usage: qnx-runner --stdio [--allow-file F] [--spawn-log F]\n"
        "       qnx-runner --listen PORT --token-file F [--bind ADDR] [--allow-file F] [--spawn-log F]\n");
    exit(64);
}

int main(int argc, char **argv) {
    int stdio = 0, port = 0;
    const char *bind_addr = "0.0.0.0", *token_file = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stdio")) stdio = 1;
        else if (!strcmp(argv[i], "--listen") && i + 1 < argc) port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--bind") && i + 1 < argc) bind_addr = argv[++i];
        else if (!strcmp(argv[i], "--token-file") && i + 1 < argc) token_file = argv[++i];
        else if (!strcmp(argv[i], "--allow-file") && i + 1 < argc) g_allow_file = argv[++i];
        else if (!strcmp(argv[i], "--spawn-log") && i + 1 < argc) g_spawn_log = argv[++i];
        else usage();
    }
    signal(SIGPIPE, SIG_IGN);
    if (stdio) {
        if (token_file) g_token = read_token_file(token_file);
        handle(0, 1);
        return 0;
    }
    if (port <= 0 || port > 65535 || !token_file) usage();
    g_token = read_token_file(token_file); /* network mode: token mandatory */

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_addr, &a.sin_addr) != 1) { fprintf(stderr, "bad --bind\n"); return 64; }
    if (bind(s, (struct sockaddr *)&a, sizeof a) || listen(s, 16)) { perror("bind/listen"); return 71; }
    fprintf(stderr, "qnx-runner listening on %s:%d\n", bind_addr, port);
    signal(SIGCHLD, SIG_IGN); /* auto-reap connection handlers */
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; perror("accept"); continue; }
        pid_t h = fork();
        if (h == 0) {
            close(s);
            signal(SIGCHLD, SIG_DFL); /* the handler must waitpid its own child */
            struct timeval tv = { 10, 0 };
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
            handle(c, c);
            shutdown(c, SHUT_WR);
            close(c);
            _exit(0);
        }
        close(c);
    }
}
