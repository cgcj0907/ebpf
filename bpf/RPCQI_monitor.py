#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcp_monitor_combined.py
综合 TCP 监控工具（带颜色对齐）：按本地端口每 interval 秒输出 RTT、SYN 到达、已建立、重传次数
基于 bcc (eBPF)

Usage:
  sudo python3 tcp_monitor_combined.py           # 每 interval 秒输出所有端口
  sudo python3 tcp_monitor_combined.py -p 80     # 只监控端口 80
  sudo python3 tcp_monitor_combined.py -i 10 --no-color
"""
from __future__ import print_function
from bcc import BPF
import argparse
from time import sleep, strftime
import os, shutil
import sys

# -------- 参数解析 --------
parser = argparse.ArgumentParser(
    description="综合 TCP 监控：RTT + SYN 到达 + 已建立 + 重传（带颜色且对齐）",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-i", "--interval", type=int, default=5,
    help="统计间隔秒数 (默认 5s)")
parser.add_argument("-p", "--port", type=int,
    help="只监控指定的本地端口")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="RTT 使用毫秒单位 (默认微秒)")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="输出时间戳")
parser.add_argument("--no-color", action="store_true",
    help="禁用颜色输出")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
interval = int(args.interval)

# ===== eBPF 程序 =====
bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

// ===== RTT 统计 =====
BPF_HASH(port_rtt_sum, u64, u64);
BPF_HASH(port_rtt_count, u64, u64);

// ===== 连接统计 =====
// port_conn_attempt: 由 tcp_v4_conn_request/tcp_v6_conn_request 计数（收到 SYN）
// port_conn_established: 由 tcp_set_state 计数（进入 ESTABLISHED）
BPF_HASH(port_conn_attempt, u64, u64);
BPF_HASH(port_conn_established, u64, u64);

// ===== 重传统计 =====
BPF_HASH(port_retrans_count, u64, u64);

// ===== 1. RTT 追踪 =====
int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = 0;
    /* srtt_us stored as (srtt << 3) in tcp_sock on many kernels */
    srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = (const struct inet_sock *)sk;

    u16 sport = 0;
    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&inet->inet_sport);
    
    FACTOR
    
    u16 sport_host = ntohs(sport);
    u64 key = (u64)sport_host;
    
    u64 *ps = port_rtt_sum.lookup(&key);
    if (ps) {
        __sync_fetch_and_add(ps, (u64)srtt);
    } else {
        u64 init = srtt;
        port_rtt_sum.update(&key, &init);
    }
    
    u64 one = 1;
    u64 *pc = port_rtt_count.lookup(&key);
    if (pc) {
        __sync_fetch_and_add(pc, one);
    } else {
        port_rtt_count.update(&key, &one);
    }
    
    return 0;
}

// ===== 2. 半连接统计：在内核收到 SYN 时计数（更可靠） =====
int trace_tcp_v4_conn_request(struct pt_regs *ctx, struct sock *sk)
{
    u16 lport = sk->__sk_common.skc_num;  // 本地端口（主机字节序）
    u64 key = (u64)lport;
    u64 one = 1;
    u64 *val = port_conn_attempt.lookup(&key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        port_conn_attempt.update(&key, &one);
    }
    return 0;
}

int trace_tcp_v6_conn_request(struct pt_regs *ctx, struct sock *sk)
{
    u16 lport = sk->__sk_common.skc_num;
    u64 key = (u64)lport;
    u64 one = 1;
    u64 *val = port_conn_attempt.lookup(&key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        port_conn_attempt.update(&key, &one);
    }
    return 0;
}

// ===== 3. 连接状态变化：统计建立 (ESTABLISHED) =====
int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    if (state != TCP_ESTABLISHED)
        return 0;

    u16 lport = sk->__sk_common.skc_num;
    u64 key = (u64)lport;
    u64 one = 1;

    u64 *val = port_conn_established.lookup(&key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        port_conn_established.update(&key, &one);
    }

    return 0;
}

// ===== 4. 重传追踪 (使用 kprobe) =====
int trace_retransmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL)
        return 0;
    
    u16 lport = sk->__sk_common.skc_num;
    u64 key = (u64)lport;
    
    u64 *val = port_retrans_count.lookup(&key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        u64 init = 1;
        port_retrans_count.update(&key, &init);
    }
    
    return 0;
}
"""

# RTT 单位处理
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'srtt /= 1000;')
    unit_label = "ms"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    unit_label = "us"

if args.ebpf:
    print(bpf_text)
    sys.exit(0)

# 加载 eBPF
print("Loading eBPF program...")
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print("BPF load failed:", e)
    sys.exit(1)

# 附加探针
print("Attaching probes...")
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")
# SYN 收到：IPv4/IPv6
# Some kernels may not have tcp_v6_conn_request exported; attach if available
try:
    b.attach_kprobe(event="tcp_v4_conn_request", fn_name="trace_tcp_v4_conn_request")
except Exception:
    # ignore if not present
    pass
try:
    b.attach_kprobe(event="tcp_v6_conn_request", fn_name="trace_tcp_v6_conn_request")
except Exception:
    pass
# ESTABLISHED
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
# retrans
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")

print("Tracing TCP metrics... Hit Ctrl-C to end")

# ---- 颜色与阈值配置 ----
NO_COLOR = bool(args.no_color)

RESET = "\033[0m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
BOLD = "\033[1m"

def color_wrap(s, color):
    if NO_COLOR:
        return s
    return f"{color}{s}{RESET}"

def thresholds_by_unit(unit):
    if unit == "ms":
        return {"high": 200, "med": 100, "trend_delta": 20, "bar_bucket": 20}
    else:
        return {"high": 200000, "med": 100000, "trend_delta": 20000, "bar_bucket": 20000}

TH = thresholds_by_unit(unit_label)

# ---- 输出格式辅助（先格式化再着色，保证宽度） ----
def fmt_port(port):
    return f"{port:6d}"

def fmt_rtt(avg):
    # avg: float
    s = f"{avg:12.2f}"
    # decide color
    if avg >= TH["high"]:
        return color_wrap(s, RED)
    elif avg >= TH["med"]:
        return color_wrap(s, YELLOW)
    else:
        return color_wrap(s, GREEN)

def fmt_trend_arrow(port, avg, last_rtt):
    prev = last_rtt.get(port)
    arrow = " "
    if prev is not None:
        diff = avg - prev
        if diff > TH["trend_delta"]:
            arrow = "↑"
        elif diff < -TH["trend_delta"]:
            arrow = "↓"
        else:
            arrow = "→"
    last_rtt[port] = avg
    return f"{arrow:>3}"

def fmt_bar(avg, max_bars=15):
    if avg <= 0:
        bar = ""
    else:
        bucket = TH["bar_bucket"]
        try:
            length = int(avg / bucket)
        except:
            length = 0
        if length > max_bars:
            length = max_bars
        bar = "█" * length
    # pad to fixed width so column alignment keeps
    bar_padded = f"{bar:<15}"
    # color bar by avg
    if avg >= TH["high"]:
        return color_wrap(bar_padded, RED)
    elif avg >= TH["med"]:
        return color_wrap(bar_padded, YELLOW)
    else:
        return color_wrap(bar_padded, GREEN)

def fmt_int_col(val, width=8, color=None):
    s = f"{val:>{width}d}"
    if color and not NO_COLOR:
        return color_wrap(s, color)
    return s

def fmt_succ(est, syn, width=8):
    if syn > 0:
        succ = (est / syn) * 100.0
        s = f"{succ:6.2f}%"
        # color by thresholds
        if succ >= 95.0:
            return color_wrap(f"{s:>{width}}", GREEN)
        elif succ >= 80.0:
            return color_wrap(f"{s:>{width}}", YELLOW)
        else:
            return color_wrap(f"{s:>{width}}", RED)
    else:
        return f"{'   N/A ':>{width}}"

# ---- 主循环 ----
last_rtt = {}
def key_to_int(k):
    try:
        return int(k.value)
    except:
        try:
            return int(k)
        except:
            return None

try:
    while True:
        sleep(interval)
        now = strftime("%H:%M:%S")

        # 取表
        rtt_sum_tbl = b.get_table("port_rtt_sum")
        rtt_cnt_tbl = b.get_table("port_rtt_count")
        conn_att_tbl = b.get_table("port_conn_attempt")       # SYN 到达计数
        conn_est_tbl = b.get_table("port_conn_established")  # ESTABLISHED 计数
        retrans_tbl = b.get_table("port_retrans_count")

        port_data = {}

        # RTT sums & counts
        for k, v in rtt_sum_tbl.items():
            port = key_to_int(k)
            if port is None: continue
            port_data.setdefault(port, {'rtt_sum': 0, 'rtt_cnt': 0, 'syn': 0, 'est': 0, 'retrans': 0})
            port_data[port]['rtt_sum'] = int(v.value)
        for k, v in rtt_cnt_tbl.items():
            port = key_to_int(k)
            if port is None: continue
            port_data.setdefault(port, {'rtt_sum': 0, 'rtt_cnt': 0, 'syn': 0, 'est': 0, 'retrans': 0})
            port_data[port]['rtt_cnt'] = int(v.value)

        # SYN 到达（由 tcp_v*_conn_request 计数）
        for k, v in conn_att_tbl.items():
            port = key_to_int(k)
            if port is None: continue
            port_data.setdefault(port, {'rtt_sum': 0, 'rtt_cnt': 0, 'syn': 0, 'est': 0, 'retrans': 0})
            port_data[port]['syn'] = int(v.value)

        # ESTABLISHED
        for k, v in conn_est_tbl.items():
            port = key_to_int(k)
            if port is None: continue
            port_data.setdefault(port, {'rtt_sum': 0, 'rtt_cnt': 0, 'syn': 0, 'est': 0, 'retrans': 0})
            port_data[port]['est'] = int(v.value)

        # retrans
        for k, v in retrans_tbl.items():
            port = key_to_int(k)
            if port is None: continue
            port_data.setdefault(port, {'rtt_sum': 0, 'rtt_cnt': 0, 'syn': 0, 'est': 0, 'retrans': 0})
            port_data[port]['retrans'] = int(v.value)

        # 过滤端口
        if args.port:
            if args.port in port_data:
                port_data = {args.port: port_data[args.port]}
            else:
                port_data = {}

        # 清屏并打印标题
        os.system("clear")
        cols = shutil.get_terminal_size().columns
        title = " TCP 监控（RTT / SYN 到达 / 已建立 / 重传） "
        print(color_wrap(title.center(cols, "="), CYAN if not NO_COLOR else ""))
        if args.timestamp:
            print(f"时间: {now}  |  间隔: {interval}s  |  RTT 单位: {unit_label}\n")
        else:
            print(f"间隔: {interval}s  |  RTT 单位: {unit_label}\n")

        if not port_data:
            print(color_wrap("（暂无数据 — 请确认有网络连接活动且以 sudo 运行）\n", YELLOW))
        else:
            # 表头（宽度固定）
            hdr = "{:>6} {:>12} {:>3} {:<15} {:>8} {:>8} {:>8} {:>8}".format(
                "PORT", f"AVG_RTT({unit_label})", "TR", "BAR", "SYN_RA", "EST", "SUCC%", "RETRANS"
            )
            print(color_wrap(hdr, BOLD + CYAN if not NO_COLOR else ""))
            print("-" * min(cols, max(80, len(hdr) + 10)))

            # 排序：活跃优先
            for port in sorted(port_data.keys(),
                               key=lambda p: -(port_data[p]['est'] + port_data[p]['retrans'] + port_data[p]['rtt_cnt'])):
                d = port_data[port]
                avg_rtt = 0.0
                if d['rtt_cnt'] > 0:
                    avg_rtt = float(d['rtt_sum']) / float(d['rtt_cnt'])
                syn = d.get('syn', 0)
                est = d.get('est', 0)
                retrans = d.get('retrans', 0)

                # prepare formatted pieces (fixed width) then color-wrap
                port_s = fmt_port(port)            # 6
                rtt_s = fmt_rtt(avg_rtt)          # 12 (inside fmt_rtt already padded)
                trend_s = fmt_trend_arrow(port, avg_rtt, last_rtt)  # 3
                bar_s = fmt_bar(avg_rtt)          # 15 padded
                syn_s = fmt_int_col(syn, width=8) # 8
                est_s = fmt_int_col(est, width=8) # 8
                succ_s = fmt_succ(est, syn, width=8) # 8 with color
                # retrans color
                if retrans > 100:
                    retrans_s = color_wrap(f"{retrans:>8d}", RED)
                elif retrans > 10:
                    retrans_s = color_wrap(f"{retrans:>8d}", YELLOW)
                else:
                    retrans_s = color_wrap(f"{retrans:>8d}", GREEN)

                # Print combined line. Note: rtt_s and bar_s already include color wrappers.
                print(f"{port_s} {rtt_s} {trend_s} {bar_s} {syn_s} {est_s} {succ_s} {retrans_s}")

        print("\n" + "=" * cols + "\n")

        # 清空 maps 准备下一个周期（增量统计）
        try:
            rtt_sum_tbl.clear()
            rtt_cnt_tbl.clear()
            conn_att_tbl.clear()
            conn_est_tbl.clear()
            retrans_tbl.clear()
        except AttributeError:
            for tbl in (rtt_sum_tbl, rtt_cnt_tbl, conn_att_tbl, conn_est_tbl, retrans_tbl):
                for key in list(tbl.keys()):
                    try:
                        del tbl[key]
                    except Exception:
                        pass

except KeyboardInterrupt:
    print("\nExiting...")
    pass
