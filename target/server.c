/* Deliberately vulnerable line-oriented TCP server.
 * Real crashes (SIGSEGV via strcpy overflow) and real OOM (unbounded ALLOC).
 * Single-threaded: a crash kills the process -> container exits -> docker restarts.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define PORT 9000
#define PASSWORD "s3cret"

static char *g_allocs[200000];   /* hold allocations so RSS grows (OOM family) */
static int   g_alloc_n = 0;

/* Separate small-frame function: overflow smashes its saved return address. */
__attribute__((noinline))
static void do_auth(int fd, char *p) {
    char user[64];
    char cred[64];
    char *sp = strchr(p, ' ');
    if (!sp) { dprintf(fd, "ERR bad auth\n"); return; }
    *sp = 0;
    strcpy(user, p);        /* VULN: overflow -> corrupts saved return addr */
    strcpy(cred, sp + 1);
    if (strcmp(cred, PASSWORD) == 0) {
        dprintf(fd, "AUTH OK\n");
    } else {
        fprintf(stderr, "auth failure for user=%s\n", user);
        dprintf(fd, "AUTH FAIL\n");
    }
}

static void handle(int fd) {
    char buf[4096];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;

        if (strncmp(buf, "PING", 4) == 0) {
            dprintf(fd, "PONG\n");
        } else if (strncmp(buf, "AUTH ", 5) == 0) {
            do_auth(fd, buf + 5);
        } else if (strncmp(buf, "ECHO ", 5) == 0) {
            dprintf(fd, "%s\n", buf + 5);
        } else if (strncmp(buf, "ALLOC ", 6) == 0) {
            long sz = atol(buf + 6);
            if (sz <= 0) sz = 1;
            char *m = malloc(sz);          /* VULN: unbounded, never freed -> OOM */
            if (m) { memset(m, 1, sz); if (g_alloc_n < 200000) g_allocs[g_alloc_n++] = m; }
            dprintf(fd, "ALLOC %ld\n", sz);
        } else if (strncmp(buf, "GET ", 4) == 0) {
            dprintf(fd, "OK 200\n");
        } else if (strncmp(buf, "RELOAD", 6) == 0) {
            /* benign clean shutdown for config reload; restart policy brings it back */
            dprintf(fd, "RELOADING\n");
            fprintf(stderr, "config reload requested; clean exit for restart\n");
            close(fd);
            exit(0);                       /* exit 0 -> clean restart, not a crash */
        } else {
            dprintf(fd, "ERR unknown\n");
        }
    }
    close(fd);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stderr, NULL, _IONBF, 0);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons(PORT);
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) < 0) { perror("bind"); return 1; }
    listen(s, 16);
    fprintf(stderr, "target listening on %d\n", PORT);
    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        fprintf(stderr, "connection accepted\n");
        handle(c);
    }
}
