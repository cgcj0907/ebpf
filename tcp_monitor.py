#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ebpf_net_monitor.py
合并 tcpconnect_rate, tcpretrans, tcprtt 的功能：
 - connect: 每 interval 按目标端口统计连接尝试/成功/成功率
 - retrans : 每 interval 按端口统计 TCP retransmits
 - rtt     : 每 interval 按端口统计平均 srtt
默认 interval = 5s。需要 bcc (python bcc).
"""
from __future__ import print_function
import argparse
from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from ctypes import c_ulonglong
import sys

parser = argparse.ArgumentParser(description="eBPF network monitor: connect/retrans/rtt per-port (interval stats)")
parser.add_argument("-i", "--interval", type=int, default=5, help="统计间隔秒 (default 5)")
parser.add_argument("-P", "--ports", help="逗号分隔的端口列表，只显示这些端口 (例如 80,443)")
parser.add_argument("--modules", help="逗号分隔启用模块: connect,retrans,rtt (default all)", default="connect,retrans,rtt")
parser.add_argument("--key", choices=["lport", "dport"], default="dport",
                    help="按哪个端口统计（connect 默认按目标端口 dport；retrans/rtt 常用 lport）。")
parser.add_argument("--rtt-us", action="store_true", help="RTT 用微秒(us)显示（默认 ms）")
parser.add_argument("--ipv4-only", action="store_true", help="只统计 IPv4")
parser.add_argument("--ipv6-only", action="store_true", help="只统计 IPv6")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

port_filter = None
if args.ports:
    try:
        port_filter = set(int(x) for x in args.ports.split(",") if x.strip())
    except:
        print("端口格式错误, 例如: -P 80,443")
        sys.exit(1)

modules = set(m.strip() for m in args.modules.split(",") if m.strip())
VALID_MODULES = {"connect", "retrans", "rtt"}
if not modules.issubset(VALID_MODULES):
    print("modules 参数错误，可选: connect,retrans,rtt")
    sys.exit(1)

# BPF program: 包含 connect trace、retrans trace、rtt trace 三部分
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

BPF_HASH(currsock_conn, u32, struct sock *);

// connect maps: key = (ipver<<16) | dport
BPF_HASH(connect_attempts, u32, u64);
BPF_HASH(connect_successes, u32, u64);

// retrans maps: key = (ipver<<16) | port
BPF_HASH(retrans_counts, u32, u64);

// rtt maps: key = (ipver<<16) | port
BPF_HASH(rtt_sum, u32, u64);
BPF_HASH(rtt_count, u32, u64);

/* ----- connect tracing ----- */
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    currsock_conn.update(&tid, &sk);
    return 0;
}

static int trace_connect_return_common(struct pt_regs *ctx, int ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct sock **skpp = currsock_conn.lookup(&tid);
    if (skpp == 0) {
        return 0;
    }
    struct sock *skp = *skpp;

    u16 dport = 0;
    dport = skp->__sk_common.skc_dport;
    dport = ntohs(dport);

    u32 key = ((u32)ipver << 16) | (u32)dport;

    u64 *val = connect_attempts.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        connect_attempts.update(&key, &one);
    }

    if (ret == 0) {
        u64 *v2 = connect_successes.lookup(&key);
        if (v2) {
            (*v2)++;
        } else {
            u64 one = 1;
            connect_successes.update(&key, &one);
        }
    }

    currsock_conn.delete(&tid);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return_common(ctx, 4);
}
int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return_common(ctx, 6);
}

/* ----- retrans tracing ----- */
/* We'll instrument tcp_retransmit_skb tracepoint or kprobe
   signature may vary; use tcp_retransmit_skb(struct sock *, struct sk_buff *) form */
int trace_retransmit_kprobe(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (!sk) return 0;
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    u16 lport = sk->__sk_common.skc_num; // host order
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);
    u32 ipver = (family == AF_INET6) ? 6 : 4;
    u32 key = ((u32)ipver << 16) | (u32)lport;

    u64 *val = retrans_counts.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        u64 one = 1;
        retrans_counts.update(&key, &one);
    }
    return 0;
}

/* tracepoint path (if available) provides args->skaddr and addresses.
   We'll also attach to tracepoint if exists using python side. */

/* ----- rtt tracing ----- */
int trace_tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (!sk) return 0;
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    // srtt stored as srtt_us >> 3 in kernel
    u32 srtt = 0;
    bpf_probe_read_kernel(&srtt, sizeof(srtt), &ts->srtt_us);
    srtt = srtt >> 3; // srtt in microseconds

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

    // pick ports (we will key using local port by default on user-side configurable)
    u16 lport = sk->__sk_common.skc_num; // host order
    u16 dport = sk->__sk_common.skc_dport;
    dport = ntohs(dport);

    u32 ipver = (family == AF_INET6) ? 6 : 4;

    // key by lport in this implementation
    u32 key = ((u32)ipver << 16) | (u32)lport;

    // store sum and count
    u64 *s = rtt_sum.lookup(&key);
    if (s) {
        (*s) += (u64)srtt;
    } else {
        u64 init = srtt;
        rtt_sum.update(&key, &init);
    }
    u64 *c = rtt_count.lookup(&key);
    if (c) {
        (*c) += 1;
    } else {
        u64 one = 1;
        rtt_count.update(&key, &one);
    }

    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    sys.exit(0)

b = BPF(text=bpf_text)

# attach probes
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

# retrans attach: try tracepoint first, otherwise kprobe
if "retrans" in modules:
    if BPF.tracepoint_exists("tcp", "tcp_retransmit_skb"):
        # attach a simple tracepoint handler that increments same map
        # We'll implement user-space handler that simply calls an empty bpf tracepoint which triggers C code path
        # But here we can attach the same kprobe function to the tracepoint name via attach_tracepoint isn't necessary
        b.attach_tracepoint(tp="tcp:tcp_retransmit_skb", fn_name="trace_retransmit_kprobe")
    else:
        b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit_kprobe")

# rtt probe
if "rtt" in modules:
    # tcp_rcv_established is a common hook used by tcprtt
    try:
        b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv_established")
    except Exception:
        # fallback: try tcp_check_timer? not ideal; ignore if missing
        pass

print("Running eBPF monitor — modules: %s   interval=%ds" % (",".join(sorted(modules)), args.interval))
print("Press Ctrl-C to stop.")

interval = int(args.interval)

def table_keys_and_vals(tbl):
    """helper: return list of (key_int, val_int)"""
    rows = []
    for k, v in tbl.items():
        # BPF returns ctypes structures; key/val usually have .value
        key = k.value if hasattr(k, "value") else int(k)
        val = v.value if hasattr(v, "value") else int(v)
        rows.append((key, val))
    return rows

try:
    while True:
        sleep(interval)
        now = strftime("%H:%M:%S")
        # gather maps
        conn_attempts = b.get_table("connect_attempts")
        conn_succ = b.get_table("connect_successes")
        retrans_tbl = b.get_table("retrans_counts")
        rtt_sum_tbl = b.get_table("rtt_sum")
        rtt_cnt_tbl = b.get_table("rtt_count")

        # collect keys across enabled modules
        keys = set()
        if "connect" in modules:
            keys |= set(k for k, _ in table_keys_and_vals(conn_attempts))
            keys |= set(k for k, _ in table_keys_and_vals(conn_succ))
        if "retrans" in modules:
            keys |= set(k for k, _ in table_keys_and_vals(retrans_tbl))
        if "rtt" in modules:
            keys |= set(k for k, _ in table_keys_and_vals(rtt_sum_tbl))
            keys |= set(k for k, _ in table_keys_and_vals(rtt_cnt_tbl))

        rows = []
        for key in sorted(keys):
            ipver = (key >> 16) & 0xffff
            port = key & 0xffff

            # ipv filter
            if args.ipv4_only and ipver != 4:
                continue
            if args.ipv6_only and ipver != 6:
                continue
            # port filter
            if port_filter is not None and port not in port_filter:
                continue

            attempts = conn_attempts.get(key)
            attempts = attempts.value if attempts is not None and hasattr(attempts, "value") else (int(attempts) if attempts is not None else 0)
            succ = conn_succ.get(key)
            succ = succ.value if succ is not None and hasattr(succ, "value") else (int(succ) if succ is not None else 0)

            retrans = retrans_tbl.get(key)
            retrans = retrans.value if retrans is not None and hasattr(retrans, "value") else (int(retrans) if retrans is not None else 0)

            rsum = rtt_sum_tbl.get(key)
            rsum = rsum.value if rsum is not None and hasattr(rsum, "value") else (int(rsum) if rsum is not None else 0)
            rcnt = rtt_cnt_tbl.get(key)
            rcnt = rcnt.value if rcnt is not None and hasattr(rcnt, "value") else (int(rcnt) if rcnt is not None else 0)

            # success rate safe compute and cap 0..100
            succ_rate_raw = (float(succ) / attempts * 100.0) if attempts > 0 else 0.0
            succ_rate = succ_rate_raw
            if succ_rate < 0:
                succ_rate = 0.0
            # cap to avoid >100 due to window misalignment
            if succ_rate > 100.0:
                capped = 100.0
            else:
                capped = succ_rate

            # rtt avg in microseconds
            avg_rtt_us = (float(rsum) / rcnt) if rcnt > 0 else 0.0
            if args.rtt_us:
                rtt_disp = f"{avg_rtt_us:.0f}us" if rcnt>0 else "-"
            else:
                # ms
                avg_rtt_ms = avg_rtt_us / 1000.0
                rtt_disp = f"{avg_rtt_ms:.2f}ms" if rcnt>0 else "-"

            rows.append((ipver, port, int(attempts), int(succ), succ_rate_raw, capped, int(retrans), rtt_disp, int(rcnt)))

        # print header and rows
        if not rows:
            print(f"{now}  (no data in this interval)")
        else:
            print()
            print(f"{now}  (interval {interval}s)")
            hdr = "%-3s %-6s %-9s %-7s %-8s %-8s %-8s %-10s %-6s" % ("IP", "PORT", "ATTEMPTS", "SUCC", "SUCC_raw", "SUCC%", "RETRANS", "AVG_RTT", "RTT_N")
            print(hdr)
            for r in sorted(rows, key=lambda x: (x[1], x[0])):
                ipver, port, attempts, succ, succ_raw, succ_cap, retrans, rtt_disp, rtt_n = r
                print("%-3d %-6d %-9d %-7d %-8.2f %-8.2f %-8d %-10s %-6d" %
                      (ipver, port, attempts, succ, succ_raw, succ_cap, retrans, rtt_disp, rtt_n))

        # clear maps for next interval (per-interval stats)
        if "connect" in modules:
            conn_attempts.clear()
            conn_succ.clear()
        if "retrans" in modules:
            retrans_tbl.clear()
        if "rtt" in modules:
            rtt_sum_tbl.clear()
            rtt_cnt_tbl.clear()

except KeyboardInterrupt:
    print("\nExiting...")
    pass
