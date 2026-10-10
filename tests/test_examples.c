/* Smoke tests for the example programs: runs echo_server/echo_client and
   two tofu_chat processes on this machine, the way a person would, with the
   driver doing the copy-pasting. Everything runs with PIERCE_LOCAL_ONLY=1 so
   no public STUN server or real router is contacted. */
#if defined(_WIN32)
#include <stdio.h>
int main(void)
{
    printf("example smoke tests use POSIX processes; skipped on Windows\n");
    return 0;
}
#else

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test.h"

static char bindir[1024];

typedef struct {
    pid_t pid;
    int in, out;            /* child's stdin (write end), stdout+stderr (read end) */
    char buf[65536];        /* everything it printed */
    size_t len;
    size_t scanned;         /* lines before this offset were already handled */
} proc;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int exe_path(const char *name, char *out, size_t cap)
{
    snprintf(out, cap, "%s/%s", bindir, name);
    return access(out, X_OK) == 0;
}

static int spawn(proc *p, char *const argv[])
{
    int in[2], out[2];
    memset(p, 0, sizeof(*p));
    if (pipe(in) < 0 || pipe(out) < 0) return -1;
    p->pid = fork();
    if (p->pid < 0) return -1;
    if (p->pid == 0) {
        dup2(in[0], 0);
        dup2(out[1], 1);
        dup2(out[1], 2);
        close(in[0]); close(in[1]); close(out[0]); close(out[1]);
        execv(argv[0], argv);
        _exit(127);
    }
    close(in[0]);
    close(out[1]);
    p->in = in[1];
    p->out = out[0];
    fcntl(p->out, F_SETFL, fcntl(p->out, F_GETFL) | O_NONBLOCK);
    return 0;
}

/* Read whatever is available, waiting up to ms. Returns 0 at EOF. */
static int drain(proc *p, int ms)
{
    struct pollfd f = {p->out, POLLIN, 0};
    if (poll(&f, 1, ms) <= 0) return 1;
    for (;;) {
        if (p->len >= sizeof(p->buf) - 1) return 1;
        ssize_t n = read(p->out, p->buf + p->len, sizeof(p->buf) - 1 - p->len);
        if (n > 0) {
            p->len += (size_t)n;
            p->buf[p->len] = 0;
            continue;
        }
        if (n == 0) return 0;
        return 1;   /* EAGAIN */
    }
}

static void say(proc *p, const char *line)
{
    ssize_t r = write(p->in, line, strlen(line));
    r = write(p->in, "\n", 1);
    (void)r;
}

static int finish(proc *p, int kill_it)
{
    int status = 0;
    if (kill_it) kill(p->pid, SIGTERM);
    for (int i = 0; i < 300; i++) {
        drain(p, 10);
        if (waitpid(p->pid, &status, WNOHANG) == p->pid) break;
        if (i == 299) {
            kill(p->pid, SIGKILL);
            waitpid(p->pid, &status, 0);
        }
    }
    close(p->in);
    close(p->out);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static void dump(const char *who, const proc *p)
{
    fprintf(stderr, "----- %s output -----\n%s\n---------------------\n", who, p->buf);
}

/* ------------------------------------------------------------------ */

static void test_echo(void)
{
    char server[1100], client[1100];
    if (!exe_path("echo_server", server, sizeof(server)) || !exe_path("echo_client", client, sizeof(client))) {
        fprintf(stderr, "  (echo examples not built; skipped)\n");
        return;
    }
    proc srv, cli;
    char addr[32], invite[600] = "";
    /* Find a free port: echo_server exits if it cannot bind. */
    for (int attempt = 0; attempt < 10 && !invite[0]; attempt++) {
        snprintf(addr, sizeof(addr), "127.0.0.1:%d", 20000 + (int)(now_ms() % 30000) + attempt);
        char *argv[] = {server, addr, NULL};
        REQUIRE(spawn(&srv, argv) == 0);
        int64_t end = now_ms() + 3000;
        while (now_ms() < end && !strstr(srv.buf, "invite: ") && drain(&srv, 50)) {
        }
        char *iv = strstr(srv.buf, "invite: ");
        if (iv && strchr(iv, '\n')) {
            sscanf(iv + 8, "%599s", invite);
        } else {
            finish(&srv, 1);
        }
    }
    REQUIRE(invite[0]);

    char *cargv[] = {client, invite, "3", NULL};
    REQUIRE(spawn(&cli, cargv) == 0);
    int64_t end = now_ms() + 10000;
    while (now_ms() < end && drain(&cli, 50)) drain(&srv, 0);
    int code = finish(&cli, 0);
    CHECK_EQ(code, 0);
    CHECK(strstr(cli.buf, "connected") != NULL);
    CHECK(strstr(cli.buf, "echo: ping 2") != NULL);
    CHECK(strstr(cli.buf, "rtt ") != NULL);
    for (int i = 0; i < 20 && !strstr(srv.buf, "gone"); i++) drain(&srv, 50);
    CHECK(strstr(srv.buf, "connected from 127.0.0.1") != NULL);
    CHECK(strstr(srv.buf, "gone: connection closed") != NULL);
    if (code != 0) {
        dump("echo_client", &cli);
        dump("echo_server", &srv);
    }
    finish(&srv, 1);
}

/* ------------------------------------------------------------------ */

/* Forward new "pierce:" lines from one chat to the other, as a person would. */
static void relay_blobs(proc *from, proc *to)
{
    char *line = from->buf + from->scanned;
    char *nl;
    while ((nl = strchr(line, '\n'))) {
        char *s = line;
        while (*s == ' ') s++;
        if (!strncmp(s, "pierce:", 7)) {
            char blob[4096];
            size_t n = (size_t)(nl - s);
            if (n < sizeof(blob)) {
                memcpy(blob, s, n);
                blob[n] = 0;
                say(to, blob);
            }
        }
        line = nl + 1;
    }
    from->scanned = (size_t)(line - from->buf);
}

/* One chat session: alice hosts, `joiner` (with its key file) joins.
   Returns 1 if the joiner's message reached the host. */
static int chat_session(const char *chat, const char *dir, const char *joiner_name, const char *joiner_key,
                        proc *host, proc *join, int expect_refusal)
{
    char akey[1100], aknown[1100], jkey[1100], jknown[1100];
    snprintf(akey, sizeof(akey), "%s/alice.key", dir);
    snprintf(aknown, sizeof(aknown), "%s/alice.known", dir);
    snprintf(jkey, sizeof(jkey), "%s/%s", dir, joiner_key);
    snprintf(jknown, sizeof(jknown), "%s/%s.known", dir, joiner_key);
    char *hargv[] = {(char *)chat, "host", "--name", "alice", "--key", akey, "--known", aknown, NULL};
    if (spawn(host, hargv) < 0) return 0;

    /* The invite is the indented line after "Give this invite". */
    char invite[512] = "";
    int64_t end = now_ms() + 5000;
    while (now_ms() < end && !invite[0]) {
        drain(host, 50);
        char *g = strstr(host->buf, "Give this invite to your peer:\n");
        if (g) {
            char *l = g + strlen("Give this invite to your peer:\n");
            if (strchr(l, '\n')) sscanf(l, "%511s", invite);
        }
    }
    if (!invite[0]) return 0;

    char *jargv[] = {(char *)chat, "join", "--name", (char *)joiner_name, "--key", jkey, "--known", jknown, invite, NULL};
    if (spawn(join, jargv) < 0) return 0;

    int sent = 0;
    end = now_ms() + 15000;
    while (now_ms() < end) {
        drain(host, 20);
        drain(join, 20);
        relay_blobs(host, join);
        relay_blobs(join, host);
        if (expect_refusal && strstr(host->buf, "DIFFERENT key")) return 0;
        if (!sent && strstr(host->buf, "connected (") && strstr(join->buf, "connected (")) {
            say(join, "hello from the smoke test");
            sent = 1;
        }
        if (strstr(host->buf, "> hello from the smoke test")) return 1;
    }
    return 0;
}

static void test_tofu_chat(void)
{
    char chat[1100];
    if (!exe_path("tofu_chat", chat, sizeof(chat))) {
        fprintf(stderr, "  (tofu_chat not built; skipped)\n");
        return;
    }
    char dir[] = "/tmp/pierce-smoke-XXXXXX";
    REQUIRE(mkdtemp(dir) != NULL);
    proc h, j;

    /* 1. First meeting: bob is new, trusted on first use. */
    int ok = chat_session(chat, dir, "bob", "bob.key", &h, &j, 0);
    CHECK(ok);
    CHECK(strstr(h.buf, "new peer, trusting on first use: bob") != NULL);
    CHECK(strstr(j.buf, "connected (direct)") != NULL);
    if (!ok) { dump("host", &h); dump("joiner", &j); }
    finish(&j, 1);
    finish(&h, 1);

    /* 2. Same key again: recognised. */
    ok = chat_session(chat, dir, "bob", "bob.key", &h, &j, 0);
    CHECK(ok);
    CHECK(strstr(h.buf, "known peer bob (key matches)") != NULL);
    if (!ok) { dump("host", &h); dump("joiner", &j); }
    finish(&j, 1);
    finish(&h, 1);

    /* 3. Someone else calling themselves bob: refused, message never arrives. */
    ok = chat_session(chat, dir, "bob", "mallory.key", &h, &j, 1);
    CHECK(!ok);
    CHECK(strstr(h.buf, "bob presented a DIFFERENT key") != NULL);
    CHECK(strstr(h.buf, "> hello") == NULL);
    finish(&j, 1);
    finish(&h, 1);

    char cmd[1200];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
    if (system(cmd) != 0) fprintf(stderr, "  (could not remove %s)\n", dir);
}

int main(int argc, char **argv)
{
    (void)argc;
    /* The examples live next to this binary in the build directory. */
    snprintf(bindir, sizeof(bindir), "%s", argv[0]);
    char *slash = strrchr(bindir, '/');
    if (slash) *slash = 0;
    else snprintf(bindir, sizeof(bindir), ".");
    setenv("PIERCE_LOCAL_ONLY", "1", 1);
    signal(SIGPIPE, SIG_IGN);   /* a refused joiner may exit while we write to it */
    RUN(test_echo);
    RUN(test_tofu_chat);
    TEST_MAIN_END();
}
#endif
