#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcpconnect_rate.py
按目标端口每 interval 秒统计 TCP 连接尝试数 / 成功数 / 成功率
基于 bcc (eBPF).
Usage:
  sudo python3 tcpconnect_rate.py            # 每5s输出一次
  sudo python3 tcpconnect_rate.py -i 2 -P 80,443
"""
from __future__ import print_function
from bcc import BPF
import argparse
from time import sleep, strftime
from ctypes import c_ulonglong
import sys

parser = argparse.ArgumentParser(description="Per-port TCP connect success rate (interval stats)")
parser.add_argument("-i", "--interval", type=int, default=5, help="统计间隔秒 (default 5)")
parser.add_argument("-P", "--ports", help="逗号分隔的目标端口列表，只显示这些端口 (例如 80,443)")
parser.add_argument("--ebpf", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()

# 允许只关注某些端口（user-space 过滤）
port_filter = None
if args.ports:
    try:
        port_filter = set(int(x) for x in args.ports.split(",") if x.strip())
    except:
        print("端口格式错误, 例如: -P 80,443")
        sys.exit(1)

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

// key: ipver (high 16 bits) | dport (low 16 bits)
// ipver: 4 or 6
BPF_HASH(attempts, u32, u64);
BPF_HASH(successes, u32, u64);
BPF_HASH(currsock, u32, struct sock *);

// store sock ptr on entry
int trace_connect_entry(struct pt_regs *ctx, struct sock *sk)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    currsock.update(&tid, &sk);
    return 0;
}

// common return handler
static int trace_connect_return(struct pt_regs *ctx, int ipver)
{
    int ret = PT_REGS_RC(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct sock **skpp = currsock.lookup(&tid);
    if (skpp == 0) {
        // missed entry: can't attribute port info -> ignore
        return 0;
    }

    struct sock *skp = *skpp;
    u16 dport = 0;
    u32 key = 0;

    // dport in sk is network order
    dport = skp->__sk_common.skc_dport;
    // convert to host order
    dport = ntohs(dport);

    key = ((u32)ipver << 16) | (u32)dport;

    // increment attempts
    u64 zero = 0, *val;
    val = attempts.lookup(&key);
    if (val) {
        (*val)++;
    } else {
        attempts.update(&key, &((u64){1}));
    }

    if (ret == 0) {
        // success
        val = successes.lookup(&key);
        if (val) {
            (*val)++;
        } else {
            successes.update(&key, &((u64){1}));
        }
    }

    // cleanup
    currsock.delete(&tid);
    return 0;
}

int trace_connect_v4_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 4);
}

int trace_connect_v6_return(struct pt_regs *ctx)
{
    return trace_connect_return(ctx, 6);
}
"""

if args.ebpf:
    print(bpf_text)
    sys.exit(0)

b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

print("Tracing connect attempts... Hit Ctrl-C to end")
interval = int(args.interval)

try:
    while True:
        sleep(interval)
        now = strftime("%H:%M:%S")
        attempts_tbl = b.get_table("attempts")
        succ_tbl = b.get_table("successes")

        # gather keys
        rows = []
        for k, v in attempts_tbl.items():
            key = k.value if hasattr(k, "value") else int(k)
            ipver = (key >> 16) & 0xffff
            dport = key & 0xffff
            attempts = v.value if isinstance(v, c_ulonglong) or hasattr(v, "value") else int(v)
            succ_val = succ_tbl.get(k)
            successes = succ_val.value if succ_val is not None else 0
            # user filter
            if port_filter is not None and dport not in port_filter:
                continue
            rows.append((ipver, dport, attempts, successes))

        if not rows:
            print(f"{now}  (no data in this interval)")
        else:
            print()
            print(f"{now}  (interval {interval}s)")
            print("%-6s %-6s %-10s %-10s %-8s" % ("IPv", "DPORT", "ATTEMPTS", "SUCC", "SUCC%"))
            for ipver, dport, attempts, successes in sorted(rows, key=lambda x: (x[1], x[0])):
                rate = (float(successes) / attempts * 100.0) if attempts > 0 else 0.0
                print("%-6d %-6d %-10d %-10d %6.2f%%" % (ipver, dport, attempts, successes, rate))

        # clear maps for next interval
        attempts_tbl.clear()
        succ_tbl.clear()

except KeyboardInterrupt:
    print("\nExiting...")
    pass
