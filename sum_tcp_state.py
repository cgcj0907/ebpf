#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from bcc import BPF
from time import sleep
import ctypes

if len(sys.argv) != 2:
    print("Usage: sudo python3 tcp_syn_filter_kprobe.py <port>")
    sys.exit(1)

FILTER_PORT = int(sys.argv[1])

prog = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/tcp.h>

BPF_HASH(syn_sent_count, u32, u64);
BPF_HASH(syn_recv_count, u32, u64);
BPF_HASH(estab_count, u32, u64);

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    u16 sport = sk->__sk_common.skc_num;

    if (sport != FILTER_PORT)
        return 0;

    u32 key = 0;
    u64 zero = 0, *val;

    if (state == TCP_SYN_SENT) {
        val = syn_sent_count.lookup_or_init(&key, &zero);
        (*val)++;
    }

    if (state == TCP_SYN_RECV) {
        val = syn_recv_count.lookup_or_init(&key, &zero);
        (*val)++;
    }

    if (state == TCP_ESTABLISHED) {
        val = estab_count.lookup_or_init(&key, &zero);
        (*val)++;
    }

    return 0;
}
"""

b = BPF(text=prog.replace("FILTER_PORT", str(FILTER_PORT)))
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")

print(f"Tracing TCP states (SYN/ESTAB) on port {FILTER_PORT} ... Ctrl-C to stop.")
print("%-10s %-12s %-12s %-12s" % ("INTERVAL", "SYN_SENT", "SYN_RECV", "ESTAB"))

key = ctypes.c_uint(0)

while True:
    sleep(5)

    sent_val = b["syn_sent_count"].get(key)
    recv_val = b["syn_recv_count"].get(key)
    estab_val = b["estab_count"].get(key)

    sent = sent_val.value if sent_val else 0
    recv = recv_val.value if recv_val else 0
    estab = estab_val.value if estab_val else 0

    print("%-10s %-12d %-12d %-12d" % ("5s", sent, recv, estab))

    b["syn_sent_count"].clear()
    b["syn_recv_count"].clear()
    b["estab_count"].clear()
