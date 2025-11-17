// ebpf_monitor.c — refined version with accurate request timing & true RPS
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <linux/sched.h>

#define PROXY_PORT 8080
#define BACKEND_PORT 8000
#ifndef TARGET_PID
#define TARGET_PID 0
#endif

// ---- TCP ----
BPF_HASH(connect_start, u64, u64);
BPF_HASH(connect_attempt_cnt, u32, u64);
BPF_HASH(connect_success_cnt, u32, u64);
BPF_HASH(retrans_count, u64, u64);

// ---- CPU ----
BPF_HISTOGRAM(sched_delay_us);
BPF_HASH(wakeup_ts, u32, u64);

// ---- HTTP timing ----
BPF_HASH(client_req_start, u64, u64);
BPF_HASH(last_send_ts, u64, u64);
BPF_HASH(backend_resp_start, u64, u64);
BPF_HISTOGRAM(proxy_req_forward_us);
BPF_HISTOGRAM(proxy_resp_forward_us);
BPF_HISTOGRAM(http_service_latency_us);

// ---- Counters ----
BPF_ARRAY(resp_counter, u64, 1);   // index 0 -> total responses

// ---- Helpers ----
static inline u16 get_lport(struct sock *sk) {
    u16 p = 0;
    bpf_probe_read_kernel(&p, sizeof(p), &sk->__sk_common.skc_num);
    return p;
}
static inline u16 get_dport(struct sock *sk) {
    u16 p = 0;
    bpf_probe_read_kernel(&p, sizeof(p), &sk->__sk_common.skc_dport);
    return ntohs(p);
}

// ---- TCP connection ----
int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;
    u64 ts = bpf_ktime_get_ns();
    u64 key = (u64)sk;
    u32 pid32 = pid;
    u64 zero = 0, *v = connect_attempt_cnt.lookup_or_init(&pid32, &zero);
    (*v)++;
    connect_start.update(&key, &ts);
    return 0;
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;
    if (state != TCP_ESTABLISHED) return 0;
    u64 key = (u64)sk;
    u64 *startp = connect_start.lookup(&key);
    if (startp) {
        u32 pid32 = pid;
        u64 zero = 0, *succ = connect_success_cnt.lookup_or_init(&pid32, &zero);
        (*succ)++;
        connect_start.delete(&key);
    }
    return 0;
}

TRACEPOINT_PROBE(tcp, tcp_retransmit_skb) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;
    struct sock *sk = (struct sock *)args->skaddr;
    if (!sk) return 0;
    u64 key = (u64)sk;
    u64 zero = 0, *v = retrans_count.lookup_or_init(&key, &zero);
    (*v)++;
    return 0;
}

// ---- CPU scheduling delay ----
TRACEPOINT_PROBE(sched, sched_wakeup) {
    u32 pid = args->pid;
    if (pid != TARGET_PID) return 0;
    u64 ts = bpf_ktime_get_ns();
    wakeup_ts.update(&pid, &ts);
    return 0;
}
TRACEPOINT_PROBE(sched, sched_switch) {
    u32 next_pid = args->next_pid;
    if (next_pid != TARGET_PID) return 0;
    u64 ts = bpf_ktime_get_ns();
    u64 *tsp = wakeup_ts.lookup(&next_pid);
    if (tsp) {
        u64 delta = ts - *tsp;
        sched_delay_us.increment(bpf_log2l(delta / 1000));
        wakeup_ts.delete(&next_pid);
    }
    return 0;
}

// ---- HTTP timing (proxy) ----
int kprobe__tcp_recvmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size, int flags) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;
    u16 lport = get_lport(sk);
    u16 dport = get_dport(sk);
    u64 ts = bpf_ktime_get_ns();
    u64 tid = bpf_get_current_pid_tgid();

    if (lport == PROXY_PORT) {
        // received first byte from client
        client_req_start.update(&tid, &ts);
    } else if (dport == BACKEND_PORT) {
        // received first byte from backend
        backend_resp_start.update(&tid, &ts);
    }
    return 0;
}

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != TARGET_PID) return 0;
    u16 lport = get_lport(sk);
    u16 dport = get_dport(sk);
    u64 ts = bpf_ktime_get_ns();
    u64 tid = bpf_get_current_pid_tgid();

    // --- Proxy -> backend: forward client request ---
    if (dport == BACKEND_PORT) {
        // record as "last send" for this tid
        last_send_ts.update(&tid, &ts);

        u64 *req_start = client_req_start.lookup(&tid);
        if (req_start) {
            // keep updating until last send
            u64 delta_us = (ts - *req_start) / 1000;
            proxy_req_forward_us.increment(bpf_log2l(delta_us));
        }
    }

    // --- Proxy -> client: send backend response ---
    if (lport == PROXY_PORT) {
        u64 *resp_start = backend_resp_start.lookup(&tid);
        u64 *req_start = client_req_start.lookup(&tid);
        if (resp_start && req_start) {
            u64 resp_us = (ts - *resp_start) / 1000;
            proxy_resp_forward_us.increment(bpf_log2l(resp_us));
            u64 svc_us = (ts - *req_start) / 1000;
            http_service_latency_us.increment(bpf_log2l(svc_us));

            client_req_start.delete(&tid);
            backend_resp_start.delete(&tid);

            // increment response counter (for RPS)
            int zero = 0;
            u64 *v = resp_counter.lookup(&zero);
            if (v)
                __sync_fetch_and_add(v, 1);
        }
    }

    return 0;
}

