#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcp_syn_monitor.py
统计 TCP 半连接（SYN_RECEIVED）和已建立连接（ESTABLISHED），并计算连接成功率
基于 BCC / eBPF

Usage:
  sudo python3 tcp_syn_monitor.py          # 每5秒输出所有端口
  sudo python3 tcp_syn_monitor.py -p 80   # 只监控端口 80
  sudo python3 tcp_syn_monitor.py -i 10   # 每10秒输出
"""

from bcc import BPF
import argparse
from time import sleep, strftime
import os, shutil

# 参数解析
parser = argparse.ArgumentParser(description="TCP SYN + EST 成功率监控")
parser.add_argument("-i", "--interval", type=int, default=5, help="统计间隔秒数")
parser.add_argument("-p", "--port", type=int, help="只监控指定端口")
args = parser.parse_args()
interval = args.interval

# ===== eBPF 程序 =====
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/tcp.h>
#include <net/sock.h>

BPF_HASH(port_syn_count, u64, u64);       // SYN_RECEIVED 次数
BPF_HASH(port_est_count, u64, u64);       // ESTABLISHED 次数

int trace_tcp_v4_conn_request(struct pt_regs *ctx, struct sock *sk) {
    u16 lport = sk->__sk_common.skc_num;
    u64 key = (u64)lport;
    u64 one = 1;
    u64 *val = port_syn_count.lookup(&key);
    if (val) {
        __sync_fetch_and_add(val, one);
    } else {
        port_syn_count.update(&key, &one);
    }
    return 0;
}

int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    if (state == TCP_ESTABLISHED) {
        u16 lport = sk->__sk_common.skc_num;
        u64 key = (u64)lport;
        u64 one = 1;
        u64 *val = port_est_count.lookup(&key);
        if (val) {
            __sync_fetch_and_add(val, one);
        } else {
            port_est_count.update(&key, &one);
        }
    }
    return 0;
}
"""

print("Loading eBPF program...")
b = BPF(text=bpf_text)

# 附加探针
b.attach_kprobe(event="tcp_v4_conn_request", fn_name="trace_tcp_v4_conn_request")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")

print("Tracing TCP SYN/EST metrics... Hit Ctrl-C to end")
print()

# 输出格式
RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
BOLD = "\033[1m"
CYAN = "\033[36m"

def key_to_int(k):
    try:
        return int(k.value)
    except:
        return int(k)

while True:
    try:
        sleep(interval)
        now = strftime("%H:%M:%S")
        syn_tbl = b.get_table("port_syn_count")
        est_tbl = b.get_table("port_est_count")

        port_data = {}
        for k, v in syn_tbl.items():
            port = key_to_int(k)
            port_data[port] = {'syn': int(v.value), 'est': 0}
        for k, v in est_tbl.items():
            port = key_to_int(k)
            if port not in port_data:
                port_data[port] = {'syn': 0, 'est': int(v.value)}
            else:
                port_data[port]['est'] = int(v.value)

        # 过滤端口
        if args.port:
            if args.port in port_data:
                port_data = {args.port: port_data[args.port]}
            else:
                port_data = {}

        # 清屏 + 标题
        os.system("clear")
        cols = shutil.get_terminal_size().columns
        title = " TCP SYN/EST 成功率监控 "
        print(f"{BOLD}{CYAN}{title.center(cols, '=')}{RESET}")
        print(f"当前时间: {now} | 统计间隔: {interval}s\n")

        if not port_data:
            print(f"{YELLOW}⚠ 暂无 TCP 数据，请检查网络活动或权限（需 sudo）...{RESET}\n")
        else:
            header = f"{'PORT':>6} {'SYN':>8} {'EST':>8} {'SUCC%':>8}"
            print(f"{BOLD}{header}{RESET}")
            print("-" * min(cols, len(header) + 20))

            for port in sorted(port_data.keys()):
                syn = port_data[port]['syn']
                est = port_data[port]['est']
                succ_rate = (est / syn * 100.0) if syn > 0 else 0.0
                if succ_rate >= 95:
                    rate_str = f"{GREEN}{succ_rate:6.2f}%{RESET}"
                elif succ_rate >= 80:
                    rate_str = f"{YELLOW}{succ_rate:6.2f}%{RESET}"
                else:
                    rate_str = f"{RED}{succ_rate:6.2f}%{RESET}"
                print(f"{port:>6d} {syn:>8d} {est:>8d} {rate_str:>8}")

        # 清空 BPF map
        try:
            syn_tbl.clear()
            est_tbl.clear()
        except AttributeError:
            for tbl in [syn_tbl, est_tbl]:
                for key in list(tbl.keys()):
                    try: del tbl[key]
                    except: pass

    except KeyboardInterrupt:
        print("\nExiting...")
        break
