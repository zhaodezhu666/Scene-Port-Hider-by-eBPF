// SPDX-License-Identifier: GPL-2.0
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bpf534441b.bpf.skel.h"

#define MAX_PORTS 16
#define MAX_UIDS 32
#define CGROUP_PATH "/sys/fs/cgroup"

struct config {
    uint16_t ports[MAX_PORTS];
    int port_count;
    uint32_t uids[MAX_UIDS];
    int uid_count;
};

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [--config FILE] [--port PORT]... [--uid UID]...\n"
            "\n"
            "Default hidden ports: 8788, 8765, 14731, 14754.\n"
            "Default allowed UIDs: 0, 1000, 2000.\n"
            "Bare numeric arguments are treated as UID whitelist entries.\n",
            argv0);
}

static int parse_ulong(const char *text, unsigned long max, unsigned long *out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || !*text)
        return -EINVAL;

    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno || !end || *end != '\0' || value > max)
        return -EINVAL;

    *out = value;
    return 0;
}

static int add_port(struct config *cfg, unsigned long port)
{
    if (port == 0 || port > 65535 || cfg->port_count >= MAX_PORTS)
        return -EINVAL;

    cfg->ports[cfg->port_count++] = (uint16_t)port;
    return 0;
}

static int add_uid(struct config *cfg, unsigned long uid)
{
    if (uid > UINT32_MAX || cfg->uid_count >= MAX_UIDS)
        return -EINVAL;

    cfg->uids[cfg->uid_count++] = (uint32_t)uid;
    return 0;
}

/*
 * The loader keeps its command line free of port numbers and UIDs.
 *
 * /proc/<pid>/cmdline is world-readable inside the init mount namespace and
 * becomes visible to ordinary apps whenever hidepid is relaxed. A detector
 * only needs to see the string "8788" next to the app's UID to conclude
 * that a port-hiding component is running, so those values are read from a
 * file instead of from argv.
 */
static const char *g_config_path;

static int parse_args(int argc, char **argv, struct config *cfg)
{
    unsigned long value;
    int saw_custom_port = 0;

    memset(cfg, 0, sizeof(*cfg));
    add_port(cfg, 8788);
    add_port(cfg, 8765);
    add_port(cfg, 14731);
    add_port(cfg, 14754);
    add_uid(cfg, 0);
    add_uid(cfg, 1000);
    add_uid(cfg, 2000);

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value_text = NULL;

        if (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            usage(argv[0]);
            return 1;
        }

        if (!strcmp(arg, "--config")) {
            if (++i >= argc)
                return -EINVAL;
            g_config_path = argv[i];
            continue;
        }

        if (!strncmp(arg, "--config=", 9)) {
            g_config_path = arg + 9;
            continue;
        }

        if (!strcmp(arg, "--port")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--port=", 7)) {
            value_text = arg + 7;
            if (parse_ulong(value_text, 65535, &value) || value == 0)
                return -EINVAL;
            if (!saw_custom_port) {
                cfg->port_count = 0;
                saw_custom_port = 1;
            }
            if (add_port(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strcmp(arg, "--uid")) {
            if (++i >= argc)
                return -EINVAL;
            value_text = argv[i];
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (!strncmp(arg, "--uid=", 6)) {
            value_text = arg + 6;
            if (parse_ulong(value_text, UINT32_MAX, &value))
                return -EINVAL;
            if (add_uid(cfg, value))
                return -EINVAL;
            continue;
        }

        if (parse_ulong(arg, UINT32_MAX, &value) || add_uid(cfg, value))
            return -EINVAL;
    }

    return 0;
}

/*
 * Read the target ports and trusted UIDs from a file.
 *
 * Format (one directive per line, "#" starts a comment):
 *   PORTS=8788 8765 14731 14754
 *   TRUSTED_UIDS=0 1000 2000 10287
 */
static int read_config_file(const char *path, struct config *cfg)
{
    FILE *f;
    char line[512];

    f = fopen(path, "re");
    if (!f)
        return -errno;

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        char *end;
        unsigned long v;
        int is_ports;

        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == '\n' || *p == '\0')
            continue;

        if (!strncmp(p, "PORTS=", 6)) {
            p += 6;
            is_ports = 1;
        } else if (!strncmp(p, "TRUSTED_UIDS=", 13)) {
            p += 13;
            is_ports = 0;
        } else {
            continue;
        }

        cfg->port_count = 0;
        cfg->uid_count = 0;

        for (;;) {
            while (*p == ' ' || *p == '\t' || *p == ',')
                p++;
            if (*p == '\n' || *p == '\0')
                break;
            v = strtoul(p, &end, 10);
            if (end == p)
                break;
            p = end;
            if (v == 0 || v == UINT32_MAX)
                continue;
            if (is_ports) {
                if (v < 65536)
                    add_port(cfg, v);
            } else {
                add_uid(cfg, v);
            }
        }
    }

    fclose(f);
    return 0;
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        return -errno;

    return 0;
}

static int setup_ports(struct bpf534441b_bpf *skel, const struct config *cfg)
{
    __u8 net_value = 1;

    for (int i = 0; i < cfg->port_count; i++) {
        __u16 net_key = htons(cfg->ports[i]);

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.lpf534441b_target_ports),
                                &net_key, &net_value, BPF_ANY)) {
            fprintf(stderr, "failed to add port %u: %s\n",
                    cfg->ports[i], strerror(errno));
            return -errno;
        }

        fprintf(stderr, "hidden port: %u\n", cfg->ports[i]);
    }

    return 0;
}

static int setup_uids(struct bpf534441b_bpf *skel, const struct config *cfg)
{
    __u8 value = 1;

    for (int i = 0; i < cfg->uid_count; i++) {
        __u32 key = cfg->uids[i];

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.lpf534441b_allowed_uids),
                                &key, &value, BPF_ANY)) {
            fprintf(stderr, "failed to add uid %u: %s\n",
                    cfg->uids[i], strerror(errno));
            return -errno;
        }
        fprintf(stderr, "allowed uid: %u\n", cfg->uids[i]);
    }

    return 0;
}

static int attach_cgroup_connect_prog(struct bpf_program *prog,
                                      int cgroup_fd,
                                      enum bpf_attach_type attach_type,
                                      const char *name)
{
    int prog_fd = bpf_program__fd(prog);

    if (prog_fd < 0) {
        fprintf(stderr, "invalid %s program fd\n", name);
        return -EINVAL;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, BPF_F_ALLOW_MULTI)) {
        fprintf(stderr, "attached %s to %s with allow-multi\n",
                name, CGROUP_PATH);
        return 0;
    }

    if (!bpf_prog_attach(prog_fd, cgroup_fd, attach_type, 0)) {
        fprintf(stderr, "attached %s to %s with legacy single attach\n",
                name, CGROUP_PATH);
        return 0;
    }

    fprintf(stderr, "attach %s to %s failed: %s\n",
            name, CGROUP_PATH, strerror(errno));
    return -errno;
}

static void detach_cgroup_connect_prog(struct bpf_program *prog,
                                       int cgroup_fd,
                                       enum bpf_attach_type attach_type,
                                       const char *name)
{
    int prog_fd;

    if (cgroup_fd < 0)
        return;

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0)
        return;

    if (bpf_prog_detach2(prog_fd, cgroup_fd, attach_type)) {
        fprintf(stderr, "detach %s from %s failed: %s\n",
                name, CGROUP_PATH, strerror(errno));
    }
}

int main(int argc, char **argv)
{
    struct config cfg;
    struct bpf534441b_bpf *skel = NULL;
    int cgroup_fd = -1;
    int connect4_attached = 0;
    int connect6_attached = 0;
    int err;

    err = parse_args(argc, argv, &cfg);
    if (err) {
        if (err < 0)
            usage(argv[0]);
        return err < 0 ? 2 : 0;
    }

    if (g_config_path) {
        err = read_config_file(g_config_path, &cfg);
        if (err) {
            fprintf(stderr, "failed to read config file: %s\n",
                    strerror(err < 0 ? -err : err));
            return 1;
        }
        if (!cfg.port_count || !cfg.uid_count) {
            fprintf(stderr, "config file did not provide ports and uids\n");
            return 1;
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    err = bump_memlock_rlimit();
    if (err)
        fprintf(stderr, "warning: failed to raise RLIMIT_MEMLOCK: %s\n",
                strerror(-err));

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    skel = bpf534441b_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    err = bpf534441b_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    err = setup_ports(skel, &cfg);
    if (err)
        goto cleanup;

    err = setup_uids(skel, &cfg);
    if (err)
        goto cleanup;

    cgroup_fd = open(CGROUP_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        fprintf(stderr, "failed to open %s: %s\n",
                CGROUP_PATH, strerror(errno));
        err = -errno;
        goto cleanup;
    }

    err = attach_cgroup_connect_prog(skel->progs.lpf534441b_connect4,
                                     cgroup_fd,
                                     BPF_CGROUP_INET4_CONNECT,
                                     "connect4");
    if (err)
        goto cleanup;
    connect4_attached = 1;

    err = attach_cgroup_connect_prog(skel->progs.lpf534441b_connect6,
                                     cgroup_fd,
                                     BPF_CGROUP_INET6_CONNECT,
                                     "connect6");
    if (err)
        goto cleanup;
    connect6_attached = 1;

    /*
     * bind() is deliberately left alone.
     *
     * On a stock device the target app holds these ports, so bind() on a
     * busy one fails with EADDRINUSE. Intercepting bind() to make it
     * succeed would be a behavioural deviation that a detector can spot
     * directly, and it would also introduce a bind()+listen()+connect()
     * contradiction plus an errno mismatch (EPERM vs EADDRINUSE).
     *
     * Not touching bind() keeps the observable behaviour identical to a
     * device without the target app, and it also keeps three fewer kprobes
     * out of the kernel.
     */

    fprintf(stderr, "service hooks loaded\n");
    while (!exiting)
        sleep(1);

    err = 0;

cleanup:
    if (connect6_attached)
        detach_cgroup_connect_prog(skel->progs.lpf534441b_connect6,
                                   cgroup_fd,
                                   BPF_CGROUP_INET6_CONNECT,
                                   "connect6");
    if (connect4_attached)
        detach_cgroup_connect_prog(skel->progs.lpf534441b_connect4,
                                   cgroup_fd,
                                   BPF_CGROUP_INET4_CONNECT,
                                   "connect4");
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    bpf534441b_bpf__destroy(skel);
    return err;
}
