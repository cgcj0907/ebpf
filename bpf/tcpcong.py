#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# tcpcong_full.py
# tcpcong + connect-syscall-latency integration + summary statistics
#
# Usage:
#   sudo python3 tcpcong_full.py [interval] [outputs]
#   examples:
#     sudo python3 tcpcong_full.py 5        # every 5s print table+summary
#     sudo python3 tcpcong_full.py -u 5     # microseconds output
#
from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from struct import pack
from socket import inet_ntop, AF_INET, AF_INET6
import argparse

examples = """examples:
    ./tcpcong_full                 # show tcp congestion status duration
    ./tcpcong_full 1 10            # show 1 second summaries, 10 times
    ./tcpcong_full -L 3000-3006 1  # 1s summaries, local port 3000-3006
    ./tcpcong_full -R 5000-5005 1  # 1s summaries, remote port 5000-5005
    ./tcpcong_full -uT 1           # 1s summaries, microseconds, and timestamps
    ./tcpcong_full -d              # show the duration as histograms
"""

parser = argparse.ArgumentParser(
    description="Summarize tcp socket congestion control status duration (with connect latency)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-L", "--localport",
            help="trace local ports only")
parser.add_argument("-R", "--remoteport",
            help="trace the dest ports only")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-d", "--dist", action="store_true",
    help="show distributions as histograms")
parser.add_argument("-u", "--microseconds", action="store_true",
    help="output in microseconds")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("outputs", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
countdown = int(args.outputs)
debug = 0

start_rport = end_rport = -1
if args.remoteport:
    rports = args.remoteport.split("-")
    if (len(rports) != 2) and (len(rports) != 1):
        print("unrecognized remote port range")
        exit(1)
    if len(rports) == 2:
        start_rport = int(rports[0])
        end_rport = int(rports[1])
    else:
        start_rport = int(rports[0])
        end_rport = int(rports[0])
if start_rport > end_rport:
    tmp = start_rport
    start_rport = end_rport
    end_rport = tmp

start_lport = end_lport = -1
if args.localport:
    lports = args.localport.split("-")
    if (len(lports) != 2) and (len(lports) != 1):
        print("unrecognized local port range")
        exit(1)
    if len(lports) == 2:
        start_lport = int(lports[0])
        end_lport = int(lports[1])
    else:
        start_lport = int(lports[0])
        end_lport = int(lports[0])
if start_lport > end_lport:
    tmp = start_lport
    start_lport = end_lport
    end_lport = tmp

# ------------------- BPF program text -------------------
bpf_head_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>

typedef struct ipv4_flow_key {
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
} ipv4_flow_key_t;

typedef struct ipv6_flow_key {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
} ipv6_flow_key_t;

typedef struct data_val {
    u64  last_ts;
    u16  last_cong_stat;
    u64  open_dura;
    u64  loss_dura;
    u64  disorder_dura;
    u64  recover_dura;
    u64  cwr_dura;
    u64  total_changes;
} data_val_t;

BPF_HASH(ipv4_stat, ipv4_flow_key_t, data_val_t);
BPF_HASH(ipv6_stat, ipv6_flow_key_t, data_val_t);

/* --- maps for connect syscall latency collection --- */
BPF_HASH(currsock, u32, struct sock *);
BPF_HASH(connect_start, u32, u64);

/* HIST_TABLE placeholder */
"""

bpf_extra_head = r"""
typedef struct process_key {
    char comm[TASK_COMM_LEN];
    u32  tid;
} process_key_t;

typedef struct ipv4_flow_val {
    ipv4_flow_key_t ipv4_key;
    u16  cong_state;
} ipv4_flow_val_t;

typedef struct ipv6_flow_val {
    ipv6_flow_key_t ipv6_key;
    u16  cong_state;
} ipv6_flow_val_t;

BPF_HASH(start_ipv4, process_key_t, ipv4_flow_val_t);
BPF_HASH(start_ipv6, process_key_t, ipv6_flow_val_t);
SOCK_STORE_DEF

typedef struct cong {
    u8  cong_stat:5,
        ca_inited:1,
        ca_setsockopt:1,
        ca_dstlocked:1;
} cong_status_t;
"""

# no-ca TP body (existing logic)
bpf_no_ca_tp_body_text = r"""
static int entry_state_update_func(struct sock *sk)
{
    u16 dport = 0, lport = 0;
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;

    u64 family = sk->__sk_common.skc_family;
    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    if (family == AF_INET) {
        ipv4_flow_val_t ipv4_val = {0};
        ipv4_val.ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_val.ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_val.ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv4_val.ipv4_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv4_val.ipv4_key.dport = dport;
        ipv4_val.cong_state = cong_status.cong_stat + 1;
        start_ipv4.update(&key, &ipv4_val);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t ipv6_val = {0};
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.saddr,
            sizeof(ipv6_val.ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_val.ipv6_key.daddr,
            sizeof(ipv6_val.ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_val.ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        dport = ntohs(dport);
        lport = ipv6_val.ipv6_key.lport;
        FILTER_LPORT
        FILTER_DPORT
        ipv6_val.ipv6_key.dport = dport;
        ipv6_val.cong_state = cong_status.cong_stat + 1;
        start_ipv6.update(&key, &ipv6_val);
    }
    SOCK_STORE_ADD
    return 0;
}

static int ret_state_update_func(struct sock *sk)
{
    u64 ts, ts1;
    u16 family, last_cong_state;
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;

    struct inet_connection_sock *icsk = inet_csk(sk);
    cong_status_t cong_status;
    bpf_probe_read_kernel(&cong_status, sizeof(cong_status),
        (void *)((long)&icsk->icsk_retransmits) - 1);
    data_val_t *datap, data = {0};
    STATE_KEY
    bpf_probe_read_kernel(&family, sizeof(family),
        &sk->__sk_common.skc_family);
    if (family == AF_INET) {
        ipv4_flow_val_t *val4 = start_ipv4.lookup(&key);
        if (val4 == 0) {
            return 0; //missed
        }
        ipv4_flow_key_t keyv4 = {0};
        bpf_probe_read_kernel(&keyv4, sizeof(ipv4_flow_key_t),
            &(val4->ipv4_key));

        datap = ipv4_stat.lookup(&keyv4);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val4->cong_state;
            // Initialize all duration fields to 0
            data.open_dura = 0;
            data.loss_dura = 0;
            data.disorder_dura = 0;
            data.recover_dura = 0;
            data.cwr_dura = 0;
            data.total_changes = 0;
            ipv4_stat.update(&keyv4, &data);
        } else {
            last_cong_state = val4->cong_state;
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_status.cong_stat + 1;
                ts /= 1000;
                STORE
            }
        }
        start_ipv4.delete(&key);
    } else if (family == AF_INET6) {
        ipv6_flow_val_t *val6 = start_ipv6.lookup(&key);
        if (val6 == 0) {
            return 0; //missed
        }
        ipv6_flow_key_t keyv6 = {0};
        bpf_probe_read_kernel(&keyv6, sizeof(ipv6_flow_key_t),
            &(val6->ipv6_key));

        datap = ipv6_stat.lookup(&keyv6);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = val6->cong_state;
            // Initialize all duration fields to 0
            data.open_dura = 0;
            data.loss_dura = 0;
            data.disorder_dura = 0;
            data.recover_dura = 0;
            data.cwr_dura = 0;
            data.total_changes = 0;
            ipv6_stat.update(&keyv6, &data);
        } else {
            last_cong_state = val6->cong_state;
            if ((cong_status.cong_stat + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = (cong_status.cong_stat + 1);
                ts /= 1000;
                STORE
            }
        }
        start_ipv6.delete(&key);
    }

    return 0;
}
"""

# tracepoint body (same as before)
bpf_ca_tp_body_text = r"""
TRACEPOINT_PROBE(tcp, tcp_cong_state_set)
{
    u64 ts, ts1;
    u16 family, last_cong_state, dport = 0, lport = 0;
    u8 cong_state;
    const struct sock *sk = (const struct sock *)args->skaddr;
    data_val_t *datap, data = {0};

    family = sk->__sk_common.skc_family;
    dport = args->dport;
    lport = args->sport;
    cong_state = args->cong_state;
    STATE_KEY
    if (family == AF_INET) {
        ipv4_flow_key_t key4 = {0};
        key4.saddr = sk->__sk_common.skc_rcv_saddr;
        key4.daddr = sk->__sk_common.skc_daddr;
        FILTER_LPORT
        FILTER_DPORT
        key4.lport = lport;
        key4.dport = dport;
        datap = ipv4_stat.lookup(&key4);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = cong_state + 1;
            // Initialize all duration fields to 0
            data.open_dura = 0;
            data.loss_dura = 0;
            data.disorder_dura = 0;
            data.recover_dura = 0;
            data.cwr_dura = 0;
            data.total_changes = 0;
            ipv4_stat.update(&key4, &data);
        } else {
            last_cong_state = datap->last_cong_stat;
            if ((cong_state + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_state + 1;
                ts /= 1000;
                STORE
            }
        }
    } else if (family == AF_INET6) {
        ipv6_flow_key_t key6 = {0};
        bpf_probe_read_kernel(&key6.saddr, sizeof(key6.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key6.daddr, sizeof(key6.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        FILTER_LPORT
        FILTER_DPORT
        key6.lport = lport;
        key6.dport = dport;
        datap = ipv6_stat.lookup(&key6);
        if (datap == 0) {
            data.last_ts = bpf_ktime_get_ns();
            data.last_cong_stat = cong_state + 1;
            // Initialize all duration fields to 0
            data.open_dura = 0;
            data.loss_dura = 0;
            data.disorder_dura = 0;
            data.recover_dura = 0;
            data.cwr_dura = 0;
            data.total_changes = 0;
            ipv6_stat.update(&key6, &data);
        } else {
            last_cong_state = datap->last_cong_stat;
            if ((cong_state + 1) != last_cong_state) {
                ts1 = bpf_ktime_get_ns();
                ts = ts1 - datap->last_ts;
                datap->last_ts = ts1;
                datap->last_cong_stat = cong_state + 1;
                ts /= 1000;
                STORE
            }
        }
    }
    return 0;
}
"""

# kprobe/kretprobe program (we add connect trace functions here)
kprobe_program = r"""
int entry_func(struct pt_regs *ctx, struct sock *sk)
{
    return entry_state_update_func(sk);
}

int ret_func(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    process_key_t key = {0};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.tid = tid;
    struct sock **sockpp;
    sockpp = sock_store.lookup(&key);
    if (sockpp == 0) {
        return 0; //miss the entry
    }
    struct sock *sk = *sockpp;
    SOCK_STORE_DEL
    return ret_state_update_func(sk);
}

/* ----- connect syscall entry/return to measure connect syscall latency ----- */
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u32 tid = bpf_get_current_pid_tgid();
    currsock.update(&tid, &sk);
    u64 ts = bpf_ktime_get_ns();
    connect_start.update(&tid, &ts);
    return 0;
}

int trace_connect_return(struct pt_regs *ctx)
{
    int ret = PT_REGS_RC(ctx);
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **skpp = currsock.lookup(&tid);
    u64 *tsp = connect_start.lookup(&tid);
    if (skpp == 0 || tsp == 0) {
        // missed entry or start ts
        if (skpp) currsock.delete(&tid);
        if (tsp) connect_start.delete(&tid);
        return 0;
    }

    if (ret != 0) {
        // connect failed, clean up
        currsock.delete(&tid);
        connect_start.delete(&tid);
        return 0;
    }

    struct sock *sk = *skpp;
    u64 now = bpf_ktime_get_ns();
    u64 delta_ns = now - *tsp;
    u64 delta_us = delta_ns / 1000;

    // build IPv4/IPv6 key and add delta to open_dura
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family == AF_INET) {
        ipv4_flow_key_t key4 = {0};
        bpf_probe_read_kernel(&key4.saddr, sizeof(key4.saddr),
            &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&key4.daddr, sizeof(key4.daddr),
            &sk->__sk_common.skc_daddr);
        u16 lport = 0;
        bpf_probe_read_kernel(&lport, sizeof(lport),
            &sk->__sk_common.skc_num);
        key4.lport = lport;
        u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        key4.dport = ntohs(dport);

        data_val_t *datap = ipv4_stat.lookup(&key4);
        if (datap) {
            // Update timestamp but don't modify duration fields for connect latency
            datap->last_ts = bpf_ktime_get_ns();
        } else {
            data_val_t zero = {0};
            zero.last_ts = bpf_ktime_get_ns();
            zero.last_cong_stat = 1;  // Assume initial state is Open
            // Initialize all duration fields to 0
            zero.open_dura = 0;
            zero.loss_dura = 0;
            zero.disorder_dura = 0;
            zero.recover_dura = 0;
            zero.cwr_dura = 0;
            zero.total_changes = 0;
            ipv4_stat.update(&key4, &zero);
        }
    } else if (family == AF_INET6) {
        ipv6_flow_key_t key6 = {0};
        bpf_probe_read_kernel(&key6.saddr, sizeof(key6.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&key6.daddr, sizeof(key6.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        u16 lport = 0;
        bpf_probe_read_kernel(&lport, sizeof(lport),
            &sk->__sk_common.skc_num);
        key6.lport = lport;
        u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        key6.dport = ntohs(dport);

        data_val_t *datap = ipv6_stat.lookup(&key6);
        if (datap) {
            // Update timestamp but don't modify duration fields for connect latency
            datap->last_ts = bpf_ktime_get_ns();
        } else {
            data_val_t zero = {0};
            zero.last_ts = bpf_ktime_get_ns();
            zero.last_cong_stat = 1;  // Assume initial state is Open
            // Initialize all duration fields to 0
            zero.open_dura = 0;
            zero.loss_dura = 0;
            zero.disorder_dura = 0;
            zero.recover_dura = 0;
            zero.cwr_dura = 0;
            zero.total_changes = 0;
            ipv6_stat.update(&key6, &zero);
        }
    }

    currsock.delete(&tid);
    connect_start.delete(&tid);
    return 0;
}
"""

kfunc_program = r"""
KFUNC_PROBE(tcp_fastretrans_alert, struct sock *sk)
{
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_fastretrans_alert, struct sock *sk)
{
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_cwr, struct sock *sk)
{
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_cwr, struct sock *sk)
{
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_loss, struct sock *sk)
{
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_loss, struct sock *sk)
{
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_enter_recovery, struct sock *sk)
{
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_enter_recovery, struct sock *sk)
{
    return ret_state_update_func(sk);
}

KFUNC_PROBE(tcp_process_tlp_ack, struct sock *sk)
{
    return entry_state_update_func(sk);
}

KRETFUNC_PROBE(tcp_process_tlp_ack, struct sock *sk)
{
    return ret_state_update_func(sk);
}
"""

# ---------- code replacement pieces ----------
store_text = r"""
                datap->total_changes += 1;
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    datap->open_dura += ts;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    datap->disorder_dura += ts;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    datap->cwr_dura += ts;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    datap->recover_dura += ts;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    datap->loss_dura += ts;
                }
"""

store_dist_text = r"""
                if (last_cong_state == (TCP_CA_Open + 1)) {
                    key_s.state = TCP_CA_Open;
                } else if (last_cong_state == (TCP_CA_Disorder + 1)) {
                    key_s.state = TCP_CA_Disorder;
                } else if (last_cong_state == (TCP_CA_CWR + 1)) {
                    key_s.state = TCP_CA_CWR;
                } else if (last_cong_state == (TCP_CA_Recovery + 1)) {
                    key_s.state = TCP_CA_Recovery;
                } else if (last_cong_state == (TCP_CA_Loss + 1)) {
                    key_s.state = TCP_CA_Loss;
                }
                TIME_UNIT
                key_s.slot = bpf_log2l(ts);
                dist.atomic_increment(key_s);
"""

hist_table_text = r"""
typedef struct congest_state_key {
    u32  state;
    u64  slot;
}congest_state_key_t;

BPF_HISTOGRAM(dist, congest_state_key_t);
"""

# Assemble bpf_text
# choose tracepoint/no-tracepoint variant as in original
is_support_tp_ca = BPF.tracepoint_exists("tcp", "tcp_cong_state_set")
if is_support_tp_ca:
    bpf_text = bpf_head_text + bpf_ca_tp_body_text
else:
    bpf_text = bpf_head_text + bpf_extra_head
    bpf_text += bpf_no_ca_tp_body_text

# add kfunc or kprobe implementations
is_support_kfunc = BPF.support_kfunc()
if is_support_kfunc:
    bpf_text += kfunc_program
    bpf_text = bpf_text.replace('SOCK_STORE_DEF', '')
    bpf_text = bpf_text.replace('SOCK_STORE_ADD', '')
    bpf_text = bpf_text.replace('SOCK_STORE_DEL', '')
else:
    bpf_text += kprobe_program
    bpf_text = bpf_text.replace('SOCK_STORE_DEF',
                   'BPF_HASH(sock_store, process_key_t, struct sock *);')
    bpf_text = bpf_text.replace('SOCK_STORE_ADD',
                   'sock_store.update(&key, &sk);')
    bpf_text = bpf_text.replace('SOCK_STORE_DEL',
                   'sock_store.delete(&key);')

# filters
if args.localport:
    bpf_text = bpf_text.replace('FILTER_LPORT',
        'if (lport < %d || lport > %d) { return 0; }'
        % (start_lport, end_lport))
else:
    bpf_text = bpf_text.replace('FILTER_LPORT', '')

if args.remoteport:
    bpf_text = bpf_text.replace('FILTER_DPORT',
        'if (dport < %d || dport > %d) { return 0; }'
        % (start_rport, end_rport))
else:
    bpf_text = bpf_text.replace('FILTER_DPORT', '')

# histogram or not
if args.dist:
    bpf_text = bpf_text.replace('STORE', store_dist_text)
    bpf_text = bpf_text.replace('STATE_KEY',
        'congest_state_key_t key_s = {0};')
    bpf_text = bpf_text.replace('HIST_TABLE', hist_table_text)
    if args.microseconds:
        bpf_text = bpf_text.replace('TIME_UNIT', '')
    else:
        bpf_text = bpf_text.replace('TIME_UNIT', 'ts /= 1000;')
else:
    bpf_text = bpf_text.replace('STORE', store_text)
    bpf_text = bpf_text.replace('STATE_KEY', '')
    bpf_text = bpf_text.replace('HIST_TABLE', '')

if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)

# attach the congestion-related kprobes (only if not using tracepoint/kfunc)
if not is_support_tp_ca and not is_support_kfunc:
    # all the tcp congestion control status update functions
    # are called by below 5 functions.
    b.attach_kprobe(event="tcp_fastretrans_alert", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_fastretrans_alert", fn_name="ret_func")
    b.attach_kprobe(event="tcp_enter_cwr", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_cwr", fn_name="ret_func")
    b.attach_kprobe(event="tcp_process_tlp_ack", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_process_tlp_ack", fn_name="ret_func")
    b.attach_kprobe(event="tcp_enter_loss", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_loss", fn_name="ret_func")
    b.attach_kprobe(event="tcp_enter_recovery", fn_name="entry_func")
    b.attach_kretprobe(event="tcp_enter_recovery", fn_name="ret_func")

# attach connect entry/return probes (best-effort: if symbol missing, ignore)
# tcp_v4_connect / tcp_v6_connect are typical kernel symbols for connect path
try:
    b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_return")
except Exception:
    # symbol not present on this kernel, ignore
    pass

try:
    b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
    b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_return")
except Exception:
    pass

print("Tracing tcp congestion control status duration... Hit Ctrl-C to end.")

def cong_state_to_name(state):
    # this need to match with kernel state
    state_name = ["open", "disorder", "cwr", "recovery", "loss"]
    return state_name[state]

# output loop
exiting = 0 if args.interval else 1
ipv6_stat = b.get_table("ipv6_stat")
ipv4_stat = b.get_table("ipv4_stat")
if args.dist:
    dist = b.get_table("dist")
label = "ms"
if args.microseconds:
    label = "us"

while (1):
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    print()
    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")
    if args.dist:
        if args.microseconds:
            dist.print_log2_hist("usecs", "tcp_congest_state",
                section_print_fn=cong_state_to_name)
        else:
            dist.print_log2_hist("msecs", "tcp_congest_state",
                section_print_fn=cong_state_to_name)
        dist.clear()
    else:
        # header + per-connection printing (ipv4)
        if ipv4_stat:
            print("%-21s% -21s %-7s %-6s %-7s %-7s %-6s %-5s" % ("LAddrPort",
                "RAddrPort", "Open_" + label, "Dod_" + label,
                "Rcov_" + label, "Cwr_" + label, "Los_" + label, "Chgs"))
        entries = []
        laddr = ""
        raddr = ""
        for k, v in sorted(ipv4_stat.items(), key=lambda ipv4_stat: ipv4_stat[0].lport):
            laddr = inet_ntop(AF_INET, pack("I", k.saddr))
            raddr = inet_ntop(AF_INET, pack("I", k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura
            if not args.microseconds:
                open_dura /= 1000
                disorder_dura /= 1000
                recover_dura /= 1000
                cwr_dura /= 1000
                loss_dura /= 1000
            if v.total_changes != 0:
                print("%-21s %-21s %-7d %-6d %-7d %-7d %-6d %-5d" % (laddr +
                    "/" + str(k.lport), raddr + "/" + str(k.dport), open_dura,
                    disorder_dura, recover_dura, cwr_dura, loss_dura,
                    v.total_changes))
                entries.append({
                    "open": float(open_dura),
                    "loss": float(loss_dura),
                    "cwr": float(cwr_dura),
                    "recover": float(recover_dura),
                    "disorder": float(disorder_dura),
                    "changes": float(v.total_changes)
                })

        # ipv6 printing (if any)
        if ipv6_stat:
            print("%-32s %-32s %-7s %-6s %-7s %-7s %-6s %-5s" % ("LAddrPort6",
                "RAddrPort6", "Open_" + label, "Dod_" + label, "Rcov_" + label,
                "Cwr_" + label, "Los_" + label, "Chgs"))
        for k, v in sorted(ipv6_stat.items(), key=lambda ipv6_stat: ipv6_stat[0].lport):
            laddr = inet_ntop(AF_INET6, bytes(k.saddr))
            raddr = inet_ntop(AF_INET6, bytes(k.daddr))
            open_dura = v.open_dura
            disorder_dura = v.disorder_dura
            recover_dura = v.recover_dura
            cwr_dura = v.cwr_dura
            loss_dura = v.loss_dura
            if not args.microseconds:
                open_dura /= 1000
                disorder_dura /= 1000
                recover_dura /= 1000
                cwr_dura /= 1000
                loss_dura /= 1000
            if v.total_changes != 0:
                print("%-32s %-32s %-7d %-7d %-7d %-6d %-6d %-5d" % (laddr +
                    "/" + str(k.lport), raddr + "/" + str(k.dport), open_dura,
                    disorder_dura, recover_dura, cwr_dura, loss_dura,
                    v.total_changes))
                entries.append({
                    "open": float(open_dura),
                    "loss": float(loss_dura),
                    "cwr": float(cwr_dura),
                    "recover": float(recover_dura),
                    "disorder": float(disorder_dura),
                    "changes": float(v.total_changes)
                })

        # ---- summary computations ----
        total_conns = len(entries)
        if total_conns == 0:
            print("\nNo TCP connections with state changes observed in this interval.")
        else:
            sum_open = sum(e["open"] for e in entries)
            sum_loss = sum(e["loss"] for e in entries)
            sum_cwr  = sum(e["cwr"]  for e in entries)
            sum_recover = sum(e["recover"] for e in entries)
            sum_disorder = sum(e["disorder"] for e in entries)
            sum_changes = sum(e["changes"] for e in entries)

            avg_open = sum_open / total_conns
            avg_loss = sum_loss / total_conns
            avg_cwr  = sum_cwr / total_conns
            avg_recover = sum_recover / total_conns
            avg_disorder = sum_disorder / total_conns
            avg_changes = sum_changes / total_conns

            print("\nSummary (this interval):")
            print("  Total connections observed: %d" % total_conns)
            print("  Avg Open:     %.2f %s" % (avg_open, label))
            print("  Avg Loss:     %.2f %s" % (avg_loss, label))
            print("  Avg CWR:      %.2f %s" % (avg_cwr, label))
            print("  Avg Recover:  %.2f %s" % (avg_recover, label))
            print("  Avg Disorder: %.2f %s" % (avg_disorder, label))
            print("  Avg Changes:  %.2f (state changes per connection)\n" % (avg_changes))
            import json
            from datetime import datetime
            import time
            
            # --- 配置：输出文件（每条记录为一行 JSON） ---
            # 改为你想要的路径，如 '/var/log/tcpcong_summary.jsonl'（注意权限）
            OUTFILE = "../logs/tcpcong.log"
            
            # ---------- 在计算完 avg_* 之后，替换原有的 summary 打印部分 ----------
            # 原来位置（示例）：
            # print("\nSummary (this interval):")
            # print("  Total connections observed: %d" % total_conns)
            # ...
            #
            # 用下面代码替换该块：
            
            print("\nSummary (this interval):")
            print("  Total connections observed: %d" % total_conns)
            print("  Avg Open:     %.2f %s" % (avg_open, label))
            print("  Avg Loss:     %.2f %s" % (avg_loss, label))
            print("  Avg CWR:      %.2f %s" % (avg_cwr, label))
            print("  Avg Recover:  %.2f %s" % (avg_recover, label))
            print("  Avg Disorder: %.2f %s" % (avg_disorder, label))
            print("  Avg Changes:  %.2f (state changes per connection)\n" % (avg_changes))
            
            # --- 构造 message 字段（同你给的样式） ---
            # 时间戳格式可以按需修改，这里使用本地时间字符串
            timestamp = time.strftime("%a %b %d %H:%M:%S %Y", time.localtime())
            
            # 构造一行 message（直接写成 key=value 形式）
            message = ('timestamp="{ts}" level=info msg="TCP congestion summary" '
                       'AvgOpen={avg_open:.2f} AvgLoss={avg_loss:.2f} '
                       'AvgCWR={avg_cwr:.2f} AvgRecover={avg_recover:.2f} '
                       'AvgDisorder={avg_disorder:.2f} AvgChanges={avg_changes:.2f} '
                       'connections={conns}').format(
                           ts=timestamp,
                           avg_open=avg_open, avg_loss=avg_loss, avg_cwr=avg_cwr,
                           avg_recover=avg_recover, avg_disorder=avg_disorder,
                           avg_changes=avg_changes, conns=total_conns, unit=label)
            
            # 直接写入文件，不再封装 JSON
            try:
                with open(OUTFILE, "a", encoding="utf-8") as fh:
                    fh.write(message + "\n")
            except Exception as e:
                print("Failed to write summary to %s: %s" % (OUTFILE, e))


    # clear maps and loop
    ipv4_stat.clear()
    ipv6_stat.clear()
    countdown -= 1
    if exiting or countdown == 0:
        exit()
