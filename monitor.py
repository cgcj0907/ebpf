#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tcp_monitor_combined.py
综合 TCP 监控工具：按本地端口每 5 秒输出 RTT、连接数、重传次数
基于 bcc (eBPF)

Usage:
  sudo python3 tcp_monitor_combined.py           # 每5s输出所有端口
  sudo python3 tcp_monitor_combined.py -p 80     # 只监控端口 80
  sudo python3 tcp_monitor_combined.py -i 10     # 每10s输出
"""

from __future__ import print_function
from bcc import BPF, tcp
import argparse
from time import sleep, strftime
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import sys

# 参数解析
parser = argparse.ArgumentParser(
    description="综合 TCP 监控：RTT + 连接数 + 重传统计",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-i", "--interval", type=int, default=5,
    help="统计间隔秒数 (默认 5s)")
parser.add_argument("-p", "--port", type=int,
    help="只监控指定的本地端口")
parser.add_argument("-m", "--milliseconds", action="store_true",
    help="RTT 使用毫秒单位 (默认微秒)")
parser.add_argument("-T", "--timestamp", action="store_true",
    help="输出时间戳")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# ===== eBPF 程序 =====
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

// ===== RTT 统计 =====
BPF_HASH(port_rtt_sum, u64, u64);
BPF_HASH(port_rtt_count, u64, u64);

// ===== 连接统计 =====
BPF_HASH(port_conn_attempt, u64, u64);   // SYN_SENT/SYN_RECV 状态进入次数
BPF_HASH(port_conn_established, u64, u64);  // ESTABLISHED 状态进入次数

// ===== 重传统计 =====
BPF_HASH(port_retrans_count, u64, u64);

// ===== 1. RTT 追踪 =====
int trace_tcp_rcv(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = ts->srtt_us >> 3;
    const struct inet_sock *inet = (struct inet_sock *)sk;

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

// ===== 2. 连接追踪 (通过状态变化) =====
int trace_tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state)
{
    // 获取旧状态
    u32 oldstate = sk->__sk_common.skc_state;
    
    // 只关心状态变化
    if (state == oldstate)
        return 0;
    
    u16 lport = sk->__sk_common.skc_num;  // 本地端口，主机字节序
    u64 key = (u64)lport;
    u64 one = 1;
    
    // 统计连接尝试：进入 SYN_SENT 或 SYN_RECV 状态
    if (state == TCP_SYN_SENT || state == TCP_SYN_RECV) {
        u64 *val = port_conn_attempt.lookup(&key);
        if (val) {
            __sync_fetch_and_add(val, 1);
        } else {
            port_conn_attempt.update(&key, &one);
        }
    }
    
    // 统计连接成功：进入 ESTABLISHED 状态
    if (state == TCP_ESTABLISHED) {
        u64 *val = port_conn_established.lookup(&key);
        if (val) {
            __sync_fetch_and_add(val, 1);
        } else {
            port_conn_established.update(&key, &one);
        }
    }
    
    return 0;
}

// ===== 3. 重传追踪 (使用 kprobe) =====
int trace_retransmit(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb)
{
    if (sk == NULL)
        return 0;
    
    u16 lport = sk->__sk_common.skc_num;  // 本地端口，主机字节序
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

# 处理 RTT 单位
if args.milliseconds:
    bpf_text = bpf_text.replace('FACTOR', 'srtt /= 1000;')
    unit_label = "ms"
else:
    bpf_text = bpf_text.replace('FACTOR', '')
    unit_label = "us"

if args.ebpf:
    print(bpf_text)
    sys.exit(0)

# 加载 eBPF 程序
print("Loading eBPF program...")
b = BPF(text=bpf_text)

# 附加探针
print("Attaching probes...")
b.attach_kprobe(event="tcp_rcv_established", fn_name="trace_tcp_rcv")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_tcp_set_state")
b.attach_kprobe(event="tcp_retransmit_skb", fn_name="trace_retransmit")

print("Tracing TCP metrics... Hit Ctrl-C to end")
print()

interval = int(args.interval)
header_printed = False

def key_to_int(k):
    """从 BPF map key 对象提取整数值"""
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
        
        # 获取所有 map
        rtt_sum_tbl = b.get_table("port_rtt_sum")
        rtt_cnt_tbl = b.get_table("port_rtt_count")
        conn_att_tbl = b.get_table("port_conn_attempt")
        conn_est_tbl = b.get_table("port_conn_established")
        retrans_tbl = b.get_table("port_retrans_count")
        
        # 收集所有端口的数据
        port_data = {}
        
        # RTT 数据
        for k, v in rtt_sum_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port not in port_data:
                port_data[port] = {'rtt_sum': 0, 'rtt_cnt': 0, 'conn_att': 0, 'conn_est': 0, 'retrans': 0}
            port_data[port]['rtt_sum'] = int(v.value)
        
        for k, v in rtt_cnt_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port not in port_data:
                port_data[port] = {'rtt_sum': 0, 'rtt_cnt': 0, 'conn_att': 0, 'conn_est': 0, 'retrans': 0}
            port_data[port]['rtt_cnt'] = int(v.value)
        
        # 连接数据
        for k, v in conn_att_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port not in port_data:
                port_data[port] = {'rtt_sum': 0, 'rtt_cnt': 0, 'conn_att': 0, 'conn_est': 0, 'retrans': 0}
            port_data[port]['conn_att'] = int(v.value)
        
        for k, v in conn_est_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port not in port_data:
                port_data[port] = {'rtt_sum': 0, 'rtt_cnt': 0, 'conn_att': 0, 'conn_est': 0, 'retrans': 0}
            port_data[port]['conn_est'] = int(v.value)
        
        # 重传数据
        for k, v in retrans_tbl.items():
            port = key_to_int(k)
            if port is None:
                continue
            if port not in port_data:
                port_data[port] = {'rtt_sum': 0, 'rtt_cnt': 0, 'conn_att': 0, 'conn_est': 0, 'retrans': 0}
            port_data[port]['retrans'] = int(v.value)
        
        # 打印表头
        if not header_printed:
            if args.timestamp:
                print("%-8s %-6s %-12s %-8s %-8s %-8s %-8s" % 
                      ("TIME", "LPORT", f"AVG_RTT({unit_label})", "CONN_ATT", "CONN_EST", "SUCC%", "RETRANS"))
            else:
                print("%-6s %-12s %-8s %-8s %-8s %-8s" % 
                      ("LPORT", f"AVG_RTT({unit_label})", "CONN_ATT", "CONN_EST", "SUCC%", "RETRANS"))
            header_printed = True
        
        # 过滤端口
        if args.port:
            if args.port in port_data:
                port_data = {args.port: port_data[args.port]}
            else:
                port_data = {}
        
        # 打印数据
        if not port_data:
            if args.timestamp:
                print("%-8s %-6s %-12s %-8s %-8s %-8s %-8s" % 
                      (now, "-", "0", "0", "0", "0.00", "0"))
            else:
                print("%-6s %-12s %-8s %-8s %-8s %-8s" % 
                      ("-", "0", "0", "0", "0.00", "0"))
        else:
            # 按活跃度排序（已建立连接 + 重传 + RTT 计数）
            for port in sorted(port_data.keys(), 
                             key=lambda p: -(port_data[p]['conn_est'] + 
                                           port_data[p]['retrans'] + 
                                           port_data[p]['rtt_cnt'])):
                data = port_data[port]
                
                # 计算平均 RTT
                avg_rtt = 0.0
                if data['rtt_cnt'] > 0:
                    avg_rtt = float(data['rtt_sum']) / float(data['rtt_cnt'])
                
                # 计算连接成功率
                succ_rate = 0.0
                if data['conn_att'] > 0:
                    succ_rate = float(data['conn_est']) / float(data['conn_att']) * 100.0
                elif data['conn_est'] > 0:
                    # 如果只有 ESTABLISHED 而没有 SYN 计数，说明是服务端接受的连接
                    # 这种情况显示 100% 或者 N/A
                    succ_rate = 100.0
                
                if args.timestamp:
                    print("%-8s %-6d %-12.2f %-8d %-8d %-8.2f %-8d" % 
                          (now, port, avg_rtt, data['conn_att'], data['conn_est'], 
                           succ_rate, data['retrans']))
                else:
                    print("%-6d %-12.2f %-8d %-8d %-8.2f %-8d" % 
                          (port, avg_rtt, data['conn_att'], data['conn_est'], 
                           succ_rate, data['retrans']))
        
        print()  # 空行分隔
        
        # 清空 maps 准备下一个周期
        try:
            rtt_sum_tbl.clear()
            rtt_cnt_tbl.clear()
            conn_att_tbl.clear()
            conn_est_tbl.clear()
            retrans_tbl.clear()
        except AttributeError:
            # 如果不支持 clear()，逐个删除
            for tbl in [rtt_sum_tbl, rtt_cnt_tbl, conn_att_tbl, conn_est_tbl, retrans_tbl]:
                for key in list(tbl.keys()):
                    try:
                        del tbl[key]
                    except:
                        pass

except KeyboardInterrupt:
    print("\nExiting...")
    pass
