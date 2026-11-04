// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * Redirect target for blocked connect() probes.
 *
 * A fixed target is a fingerprint: a detector can probe the target port
 * itself and observe that it is reachable/refused in a way that differs from
 * an ordinary closed port, or notice that every blocked port collapses onto
 * one specific number. Deriving the target from the caller's tgid spreads
 * the redirects across a wide, per-process range that is still consistently
 * unused on a stock device.
 *
 * Range 49152-65535 is the Linux ephemeral port range; those ports are only
 * momentarily in use, so a connect() to them is refused just like a closed
 * port, but the specific value differs per calling process.
 */
/*
 * Bind-rewrite master switch.
 *
 * Originally the module rewrote bind() on hidden ports to an ephemeral port
 * and back-filled getsockname(), so that a detector binding the port would
 * not learn the truth. That turns out to be self-defeating:
 *
 *   - On a stock device with the target app listening, bind() on a busy port
 *     fails with EADDRINUSE. Rewriting it makes bind() *succeed*, which is
 *     the opposite of stock behaviour and is a strong signal in itself.
 *   - It also creates a bind()+listen()+connect() contradiction and an
 *     errno mismatch (EPERM instead of EADDRINUSE).
 *
 * Leaving bind() untouched reproduces stock behaviour exactly: the kernel
 * reports EADDRINUSE for ports that are genuinely in use, and succeeds for
 * ports that are not. Only connect() needs to be intercepted.
 */
#define ENABLE_BIND_REWRITE 0

/*
 * Redirect targets live in 1024-49151, the registered-but-unassigned range.
 * The ephemeral range (49152-65535) was deliberately avoided: a local
 * service can legitimately hold an ephemeral port, and connecting to it
 * would succeed and give away that the real port is in use. Ports below
 * 1024 are equally unsuitable (privilege semantics, and port 1 in
 * particular is a well-known service). The range below is never bound
 * by normal services, so the connect reliably fails with ECONNREFUSED,
 * exactly like a closed port on a stock device.
 */
#define REDIRECT_PORT_BASE 1024U
#define REDIRECT_PORT_SPAN 48127U
#define IPV4_LOOPBACK_PREFIX 0x7f000000U
#define PORT_ORDER_NET 1
#define PORT_ORDER_HOST 2
#define MIN_SOCKADDR_PORT_LEN 4
#define MIN_SOCKADDR_IN_LEN 8
#define MIN_SOCKADDR_IN6_LEN 24

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 10
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);
    __type(value, __u8);
} lpf534441b_target_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u8);
} lpf534441b_allowed_uids SEC(".maps");

struct bind_attempt_state {
    __s32 fd;
    __u16 port;
    __u8 claim_created;
};

struct bind_rewrite_state {
    __u64 uaddr;
    __u16 port;
};

struct fd_port_key {
    __u32 tgid;
    __s32 fd;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct bind_attempt_state);
} lpf534441b_pending_bind_attempts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct fd_port_key);
    __type(value, __u16);
} lpf534441b_fd_bound_ports SEC(".maps");

/*
 * Tracks live "claims" of a hidden port by a non-whitelisted task, keyed by
 * (tgid << 32 | net-order port). The value is the pid_tgid that created the
 * speculative claim, so bind failure cleanup can avoid deleting another
 * racing thread's live claim.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} lpf534441b_bound_hidden_claims SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct bind_rewrite_state);
} lpf534441b_pending_getsockname SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct fd_port_key make_fd_key(__s32 fd)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct fd_port_key key = {};

    key.tgid = (__u32)(pid_tgid >> 32);
    key.fd = fd;
    return key;
}

static __always_inline __u64 make_claim_key(__u16 port)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    return ((__u64)tgid << 32) | (__u64)port;
}

static __always_inline int uid_is_allowed(void)
{
    __u32 uid = (__u32)bpf_get_current_uid_gid();
    __u8 *match = bpf_map_lookup_elem(&lpf534441b_allowed_uids, &uid);

    return match != 0;
}

static __always_inline __u8 target_port_order(__u16 port)
{
    __u8 *match = bpf_map_lookup_elem(&lpf534441b_target_ports, &port);

    if (!match)
        return 0;

    return *match;
}

static __always_inline int is_ipv4_local_probe(__u32 ip4)
{
    if (ip4 == 0)
        return 1;

    if ((ip4 & 0xff000000U) == IPV4_LOOPBACK_PREFIX)
        return 1;

    return (bpf_ntohl(ip4) & 0xff000000U) == IPV4_LOOPBACK_PREFIX;
}

static __always_inline int is_ipv6_local_probe(__u32 ip0, __u32 ip1,
                                               __u32 ip2, __u32 ip3)
{
    if (ip0 != 0 || ip1 != 0)
        return 0;

    if (ip2 == 0)
        return ip3 == 0 || ip3 == bpf_htonl(1) || ip3 == 1;

    if (ip2 == 0x0000ffffU || ip2 == bpf_htonl(0x0000ffffU))
        return is_ipv4_local_probe(ip3);

    return 0;
}

static __always_inline __u8 lpf534441b_redirect_order(__u16 port)
{
    __u8 order = target_port_order(port);

    if (!order)
        return 0;

    if (uid_is_allowed())
        return 0;

    return order;
}

static __always_inline __u16 port_for_sockaddr(__u16 port, __u8 order)
{
    if (order == PORT_ORDER_HOST)
        return bpf_htons(port);

    return port;
}

static __always_inline __u16 redirect_target_port(void)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);

    return (__u16)(REDIRECT_PORT_BASE + (tgid % REDIRECT_PORT_SPAN));
}

static __always_inline void redirect_connect_port(struct bpf_sock_addr *ctx,
                                                  __u8 order)
{
    __u16 port = redirect_target_port();

    if (order == PORT_ORDER_HOST)
        ctx->user_port = port;
    else
        ctx->user_port = bpf_htons(port);
}

static __always_inline int read_target_local_sockaddr(const void *uaddr,
                                                      int addrlen,
                                                      __u16 *sockaddr_port)
{
    __u16 family = 0;
    __u16 port = 0;
    __u8 order;

    if (!uaddr || addrlen < MIN_SOCKADDR_PORT_LEN)
        return 0;

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) < 0)
        return 0;

    if (bpf_probe_read_user(&port, sizeof(port), (const char *)uaddr + 2) < 0)
        return 0;

    order = lpf534441b_redirect_order(port);
    if (!order)
        return 0;

    if (family == AF_INET) {
        __u32 ip4 = 0;

        if (addrlen < MIN_SOCKADDR_IN_LEN)
            return 0;

        if (bpf_probe_read_user(&ip4, sizeof(ip4), (const char *)uaddr + 4) < 0)
            return 0;

        if (!is_ipv4_local_probe(ip4))
            return 0;
    } else if (family == AF_INET6) {
        __u32 ip0 = 0;
        __u32 ip1 = 0;
        __u32 ip2 = 0;
        __u32 ip3 = 0;

        if (addrlen < MIN_SOCKADDR_IN6_LEN)
            return 0;

        if (bpf_probe_read_user(&ip0, sizeof(ip0), (const char *)uaddr + 8) < 0 ||
            bpf_probe_read_user(&ip1, sizeof(ip1), (const char *)uaddr + 12) < 0 ||
            bpf_probe_read_user(&ip2, sizeof(ip2), (const char *)uaddr + 16) < 0 ||
            bpf_probe_read_user(&ip3, sizeof(ip3), (const char *)uaddr + 20) < 0)
            return 0;

        if (!is_ipv6_local_probe(ip0, ip1, ip2, ip3))
            return 0;
    } else {
        return 0;
    }

    *sockaddr_port = port_for_sockaddr(port, order);
    return 1;
}
#if ENABLE_BIND_REWRITE
static __always_inline int lpf534441b_maybe_rewrite_bind(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u8 order = lpf534441b_redirect_order(port);
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 claim_key;
    __u64 owner;
    __u64 *claimed;
    struct bind_attempt_state *pending;

    if (!order)
        return 1;

    /*
     * A real kernel lets only one socket hold a given local port at a time
     * (absent SO_REUSEADDR/SO_REUSEPORT). Without this guard, a probe could
     * bind the same hidden port on two fds: today both would be silently
     * rewritten to distinct ephemeral ports while getsockname() reports the
     * hidden port for both, an impossible result that fingerprints us.
     *
     * Track a per-task claim keyed by (tgid, net-order port). The first bind
     * records a speculative claim and is rewritten to an ephemeral port; a
     * second bind of the same hidden port by the same task while the claim is
     * live is rejected, matching the EADDRINUSE-style failure of a real kernel.
     * If the rewritten bind later fails, lpf534441b_bind_ret rolls back only if
     * this bind attempt created the speculative claim. This avoids deleting a
     * claim owned by an earlier successful bind from the same thread.
     */
    claim_key = make_claim_key(port);
    claimed = bpf_map_lookup_elem(&lpf534441b_bound_hidden_claims, &claim_key);
    if (claimed)
        return 0;

    owner = pid_tgid;
    if (!bpf_map_update_elem(&lpf534441b_bound_hidden_claims, &claim_key, &owner, BPF_ANY)) {
        pending = bpf_map_lookup_elem(&lpf534441b_pending_bind_attempts, &pid_tgid);
        if (pending && pending->port == port)
            pending->claim_created = 1;
    }
    ctx->user_port = 0;
    return 1;
}

#endif /* ENABLE_BIND_REWRITE */

SEC("cgroup/connect4")
int lpf534441b_connect4(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u8 order;

    if (!is_ipv4_local_probe(ctx->user_ip4))
        return 1;

    order = lpf534441b_redirect_order(port);
    if (order)
        redirect_connect_port(ctx, order);

    return 1;
}

SEC("cgroup/bind4")
int lpf534441b_bind4(struct bpf_sock_addr *ctx)
{
    /* Leave bind() semantics untouched so they match a stock device. */
    return 1;
}

SEC("cgroup/connect6")
int lpf534441b_connect6(struct bpf_sock_addr *ctx)
{
    __u16 port = (__u16)ctx->user_port;
    __u32 ip0 = ctx->user_ip6[0];
    __u32 ip1 = ctx->user_ip6[1];
    __u32 ip2 = ctx->user_ip6[2];
    __u32 ip3 = ctx->user_ip6[3];
    __u8 order;

    if (!is_ipv6_local_probe(ip0, ip1, ip2, ip3))
        return 1;

    order = lpf534441b_redirect_order(port);
    if (order)
        redirect_connect_port(ctx, order);

    return 1;
}

SEC("cgroup/bind6")
int lpf534441b_bind6(struct bpf_sock_addr *ctx)
{
    /* Leave bind() semantics untouched so they match a stock device. */
    return 1;
}

/*
 * bind()/getsockname()/close() interception is disabled by default.
 *
 * Rewriting bind() makes bind() succeed on ports a stock device would reject
 * with EADDRINUSE. That deviation is a signal in itself, and it also creates a
 * bind()+listen()+connect() contradiction plus an errno mismatch (EPERM instead
 * of EADDRINUSE). Leaving bind() untouched keeps observable behaviour identical
 * to a device without the target app, and keeps three fewer kprobes out of the
 * kernel.
 */
#if ENABLE_BIND_REWRITE
static __always_inline int record_bind_attempt(__s32 fd,
                                               const void *uaddr,
                                               int addrlen)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_attempt_state state = {};
    __u16 port = 0;

    bpf_map_delete_elem(&lpf534441b_pending_bind_attempts, &key);

    if (fd < 0)
        return 0;

    if (!read_target_local_sockaddr(uaddr, addrlen, &port))
        return 0;

    state.fd = fd;
    state.port = port;
    bpf_map_update_elem(&lpf534441b_pending_bind_attempts, &key, &state, BPF_ANY);
    return 0;
}

SEC("kprobe/__sys_bind")
int lpf534441b_bind_entry_direct(struct pt_regs *ctx)
{
    return record_bind_attempt((__s32)PT_REGS_PARM1(ctx),
                               (const void *)PT_REGS_PARM2(ctx),
                               (int)PT_REGS_PARM3(ctx));
}

SEC("kprobe/__arm64_sys_bind")
int lpf534441b_bind_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return record_bind_attempt((__s32)BPF_CORE_READ(syscall_regs, regs[0]),
                               (const void *)BPF_CORE_READ(syscall_regs, regs[1]),
                               (int)BPF_CORE_READ(syscall_regs, regs[2]));
}

SEC("kretprobe/__sys_bind")
int lpf534441b_bind_ret(struct pt_regs *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_attempt_state *state;
    __s32 fd;
    __u16 port;
    __u8 claim_created;
    long ret;

    state = bpf_map_lookup_elem(&lpf534441b_pending_bind_attempts, &key);
    if (!state)
        return 0;

    fd = state->fd;
    port = state->port;
    claim_created = state->claim_created;
    ret = PT_REGS_RC(ctx);

    if (ret == 0) {
        struct fd_port_key fd_key = make_fd_key(fd);

        bpf_map_update_elem(&lpf534441b_fd_bound_ports, &fd_key, &port, BPF_ANY);
    } else if (claim_created) {
        __u64 claim_key = make_claim_key(port);
        __u64 *owner;

        owner = bpf_map_lookup_elem(&lpf534441b_bound_hidden_claims, &claim_key);
        if (owner && *owner == key)
            bpf_map_delete_elem(&lpf534441b_bound_hidden_claims, &claim_key);
    }

    bpf_map_delete_elem(&lpf534441b_pending_bind_attempts, &key);
    return 0;
}

static __always_inline int record_getsockname_user_addr(__s32 fd, __u64 uaddr)
{
    __u64 pending_key = bpf_get_current_pid_tgid();
    struct fd_port_key fd_key = make_fd_key(fd);
    __u16 *port = bpf_map_lookup_elem(&lpf534441b_fd_bound_ports, &fd_key);
    struct bind_rewrite_state state = {};

    bpf_map_delete_elem(&lpf534441b_pending_getsockname, &pending_key);

    if (fd < 0 || !port || !uaddr)
        return 0;

    state.uaddr = uaddr;
    state.port = *port;
    bpf_map_update_elem(&lpf534441b_pending_getsockname, &pending_key, &state, BPF_ANY);
    return 0;
}

#endif /* ENABLE_BIND_REWRITE */

#if ENABLE_BIND_REWRITE
SEC("kprobe/__sys_getsockname")
int lpf534441b_getsockname_entry_direct(struct pt_regs *ctx)
{
    return record_getsockname_user_addr((__s32)PT_REGS_PARM1(ctx),
                                        (__u64)PT_REGS_PARM2(ctx));
}

SEC("kprobe/__arm64_sys_getsockname")
int lpf534441b_getsockname_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return record_getsockname_user_addr((__s32)BPF_CORE_READ(syscall_regs, regs[0]),
                                        BPF_CORE_READ(syscall_regs, regs[1]));
}

SEC("kretprobe/__sys_getsockname")
int lpf534441b_getsockname_ret(struct pt_regs *ctx)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct bind_rewrite_state *state;

    state = bpf_map_lookup_elem(&lpf534441b_pending_getsockname, &key);
    if (!state)
        return 0;

    if (PT_REGS_RC(ctx) == 0) {
        __u64 port_addr = state->uaddr + 2;
        __u16 port = state->port;

        bpf_probe_write_user((void *)port_addr, &port, sizeof(port));
    }

    bpf_map_delete_elem(&lpf534441b_pending_getsockname, &key);
    return 0;
}

static __always_inline int forget_fd(__s32 fd)
{
    struct fd_port_key key;
    __u16 *port;

    if (fd < 0)
        return 0;

    key = make_fd_key(fd);

    /*
     * Release the per-task port claim recorded at bind time so a later,
     * legitimate rebind of the same hidden port by this task is not
     * mistaken for a duplicate. lpf534441b_fd_bound_ports holds the net-order hidden
     * port this fd was bound to.
     */
    port = bpf_map_lookup_elem(&lpf534441b_fd_bound_ports, &key);
    if (port) {
        __u64 claim_key = make_claim_key(*port);

        bpf_map_delete_elem(&lpf534441b_bound_hidden_claims, &claim_key);
    }

    bpf_map_delete_elem(&lpf534441b_fd_bound_ports, &key);
    return 0;
}

SEC("kprobe/__sys_close")
int lpf534441b_close_entry_direct(struct pt_regs *ctx)
{
    return forget_fd((__s32)PT_REGS_PARM1(ctx));
}

SEC("kprobe/__arm64_sys_close")
int lpf534441b_close_entry_arm64(struct pt_regs *ctx)
{
    const struct pt_regs *syscall_regs = (const struct pt_regs *)PT_REGS_PARM1(ctx);

    return forget_fd((__s32)BPF_CORE_READ(syscall_regs, regs[0]));
}

#endif /* ENABLE_BIND_REWRITE */
