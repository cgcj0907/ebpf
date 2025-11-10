#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# tcprtt    Summarize TCP RTT as averages per local port every interval. For Linux, uses BCC, eBPF.
#
# USAGE: tcprtt [-h] [-T] [-m] [-i INTERVAL] [-d DURATION]
#           [-p LPORT] [-P RPORT] [-a LADDR] [-A RADDR]
#           [-4 | -6]
#
# Modified: aggregate average RTT per local port every interval (default 5s).
#
# Copyright (c) 2020 zhenwei pi
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 23-AUG-2020  zhenwei pi  Created this.
# Modified: produce per-port average RTT every interval.

from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from socket import inet_ntop, inet_pton, AF_INET, AF_INET6
import socket, struct
import argparse
import ctypes

# arguments
examples = """examples:
    ./tcprtt               # average RTT per LPORT every 5s
    ./tcprtt -i 1 -d 10   # 1s summaries, 10 times
    ./tcprtt -m -T        # millisecond units and timestamps
    ./tcprtt -p 80        # only record port 80 (BPF-side filter)
    ./tcprtt -4           # IPv4 only
    ./tcprtt -6           # IPv6 only
"""
parser = argparse.ArgumentParser(
    description="Average TCP RTT per local port",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-i", "--interval", type=int, default=5,
    help="summary interval (seconds). Default 5s")
parser.add_argument("-d", "--duration", type=int, default=99999,
    help="total duration of trace, seconds")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="report RTT in milliseconds (default: usecs)")
parser.add_argument("-p", "--lport",
    help="filter for local port (BPF-side: only record this local port)")
parser.add_argument("-P", "--rport",
    help="filter for remote port")
parser.add_argument("-a", "--laddr",
    help="filter for local address")
parser.add_argument("-A", "--raddr",
    help="filter for remote address")
parser.add_argument("-D", "--debug", action="store_true",
    help="print BPF program before starting (for debugging purposes)")
group = parser.add_mutually_exclusive_group()
group.add_argument("-4", "--ipv4", action="store_true",
    help="trace IPv4 family only")
group.add_argument("-6", "--ipv6", action="store_true",
    help="trace IPv6 family only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# define BPF program (adds port_sum/port_count maps keyed by u64(port))
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

BPF_HASH(port_sum, u64, u64);
BPF_HASH(port_count, u64, u64);

int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = ts->srtt_us >> 3; /* srtt in usec by kernel convention */
    const struct inet_sock *inet = (struct inet_sock *)sk;

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    __u8 saddr6[16];
    __u8 daddr6[16];
    u16 family = 0;

    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&inet->inet_dport);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);
    if (family == AF_INET6) {
        bpf_probe_read_kernel(&saddr6, sizeof(saddr6),
                              (void *)&sk->__sk_common.skc_v6_rcv_saddr.s6_addr);
        bpf_probe_read_kernel(&daddr6, sizeof(daddr6),
                              (void *)&sk->__sk_common.skc_v6_daddr.s6_addr);
    } else {
        bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&inet->inet_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&inet->inet_daddr);
    }

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER
    FAMILYFILTER

    FACTOR

    /* aggregate by local port: key is host-order port as u64 */
    {
        u16 sport_host = ntohs(sport);
        u64 key = (u64)sport_host;
        u64 *ps = port_sum.lookup(&key);
        if (ps) {
            __sync_fetch_and_add(ps, (u64)srtt);
        } else {
            u64 init = srtt;
            port_sum.update(&key, &init);
        }
        u64 one = 1;
        u64 *pc = port_count.lookup(&key);
        if (pc) {
            __sync_fetch_and_add(pc, one);
        } else {
            port_count.update(&key, &one);
        }
    }

    return 0;
}
"""

# filter for local port (-p)
if args.lport:
    bpf_text = bpf_text.replace('LPORTFILTER',
        """if (ntohs(sport) != %d)
        return 0;""" % int(args.lport))
else:
    bpf_text = bpf_text.replace('LPORTFILTER', '')

# filter for remote port (-P)
if args.rport:
    bpf_text = bpf_text.replace('RPORTFILTER',
        """if (ntohs(dport) != %d)
        return 0;""" % int(args.rport))
else:
    bpf_text = bpf_text.replace('RPORTFILTER', '')

def addrfilter(addr, src_or_dest):
    try:
        naddr = socket.inet_pton(AF_INET, addr)
    except Exception:
        # IPv6
        naddr = socket.inet_pton(AF_INET6, addr)
        # represent bytes in C string escaped hex
        s = ('\\' + struct.unpack("=16s", naddr)[0].hex('\\')).replace('\\', '\\x')
        filter = "if (memcmp(%s6, \"%s\", 16)) return 0;" % (src_or_dest, s)
    else:
        filter = "if (%s != %d) return 0;" % (src_or_dest, struct.unpack("=I", naddr)[0])
    return filter

# filter for local address (-a)
if args.laddr:
    bpf_text = bpf_text.replace('LADDRFILTER', addrfilter(args.laddr, 'saddr'))
else:
    bpf_text = bpf_text.replace('LADDRFILTER', '')

# filter for remote address (-A)
if args.raddr:
    bpf_text = bpf_text.replace('RADDRFILTER', addrfilter(args.raddr, 'daddr'))
else:
    bpf_text = bpf_text.replace('RADDRFILTER', '')

# IPv4/IPv6 family filter
if args.ipv4:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET) { return 0; }')
elif args.ipv6:
    bpf_text = bpf_text.replace('FAMILYFILTER',
        'if (family != AF_INET6) { return 0; }')
else:
    bpf_text = bpf_text.replace('FAMILYFILTER', '')

# milliseconds or usecs
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'srtt /= 1000;')
    unit_label = "msecs"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    unit_label = "usecs"

# debug/dump ebpf enable or not
if args.debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")

print("Tracing TCP RTT and aggregating per local port... Hit Ctrl-C to end.")
interval = int(args.interval)
duration = int(args.duration)
seconds = 0
exiting = 0 if interval else 1

# helper to get integer key value from BPF map key object
def key_to_int(k):
    # keys are ctypes (c_ulonglong etc). Try to extract .value
    try:
        return int(k.value)
    except Exception:
        try:
            # maybe object has .port or bytes
            return int(k)
        except Exception:
            return None

# main loop: every interval, read port_sum & port_count, compute averages
try:
    header_printed = False
    while True:
        sleep(interval)
        seconds += interval

        port_sum_tbl = b.get_table("port_sum")
        port_cnt_tbl = b.get_table("port_count")

        # build dict port -> (sum, count)
        port_stats = {}
        # read sums
        for k, v in port_sum_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            port_stats[port] = [int(v.value), 0]
        # read counts
        for k, v in port_cnt_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port in port_stats:
                port_stats[port][1] = int(v.value)
            else:
                port_stats[port] = [0, int(v.value)]

        # print header once
        if not header_printed:
            if args.timestamp:
                print("%-8s %-6s %-12s %-8s" % ("TIME", "LPORT", "AVG_RTT", "UNITS"))
            else:
                print("%-6s %-12s %-8s" % ("LPORT", "AVG_RTT", "UNITS"))
            header_printed = True

        now = strftime("%H:%M:%S")
        if not port_stats:
            # no data in this window
            if args.timestamp:
                print("%-8s %-6s %-12s %-8s" % (now, "-", 0, unit_label))
            else:
                print("%-6s %-12s %-8s" % ("-", 0, unit_label))
        else:
            # sort by count desc then port
            for p, (s, c) in sorted(port_stats.items(), key=lambda it: (-(it[1][1]), it[0])):
                avg = 0.0
                if c > 0:
                    avg = float(s) / float(c)
                # print nicely
                if args.timestamp:
                    print("%-8s %-6d %-12.2f %-8s" % (now, p, avg, unit_label))
                else:
                    print("%-6d %-12.2f %-8s" % (p, avg, unit_label))

        # clear maps for next interval (sliding-window style)
        try:
            port_sum_tbl.clear()
            port_cnt_tbl.clear()
        except AttributeError:
            # fallback to deleting keys one-by-one
            for key in list(port_sum_tbl.keys()):
                try:
                    del port_sum_tbl[key]
                except Exception:
                    pass
            for key in list(port_cnt_tbl.keys()):
                try:
                    del port_cnt_tbl[key]
                except Exception:
                    pass

        # exit when duration reached
        if seconds >= duration:
            break

except KeyboardInterrupt:
    pass

print("Exiting.")
