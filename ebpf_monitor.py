#!/usr/bin/env python3
from bcc import BPF
import threading, socket, time, sys, statistics

if len(sys.argv) != 2:
    print("Usage: sudo python3 ebpf_monitor.py <proxy_pid>")
    sys.exit(1)

proxy_pid = int(sys.argv[1])
INTERVAL = 5
UDP_PORT = 42424

# Load eBPF C source
with open("ebpf_monitor.c", "r") as f:
    csrc = f.read()
csrc = "#define TARGET_PID %d\n%s" % (proxy_pid, csrc)

# ---- HTTP Status listener ----
status_counts = {}
status_lock = threading.Lock()
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", UDP_PORT))
    sock.settimeout(1)
    while True:
        try:
            data, _ = sock.recvfrom(64)
            s = data.decode().strip()
            code = int(s.split()[0])
            with status_lock:
                status_counts[code] = status_counts.get(code, 0) + 1
        except Exception:
            pass
threading.Thread(target=udp_listener, daemon=True).start()

# ---- Load BPF ----
b = BPF(text=csrc)
print(f"[+] eBPF loaded for proxy PID={proxy_pid}")

def hist_summary(tbl):
    values = []
    for k, v in tbl.items():
        count = v.value
        # center of bucket (log2)
        mid = (1 << k.value)
        values.extend([mid] * count)
    tbl.clear()
    if not values:
        return None
    avg = statistics.mean(values)
    p50 = statistics.quantiles(values, n=100)[49]
    p90 = statistics.quantiles(values, n=100)[89]
    p95 = statistics.quantiles(values, n=100)[94]
    p99 = statistics.quantiles(values, n=100)[98]
    return dict(samples=len(values), avg=avg, p50=p50, p90=p90, p95=p95, p99=p99)

def print_hist_summary(name, tbl, desc):
    s = hist_summary(tbl)
    if not s:
        print(f"[{name}] {desc}\n  (no samples)")
        return
    print(f"[{name}] {desc}")
    print(f"  samples={s['samples']}  avg≈{s['avg']:.1f} us  "
          f"p50={int(s['p50'])}us  p90={int(s['p90'])}us  p95={int(s['p95'])}us  p99={int(s['p99'])}us")

last_resp_count = 0

import math

def fmt(v):
    if v is None: return "–"
    if v >= 1000000: return f"{v/1000:.1f}k"
    if v >= 1000: return f"{v/1000:.1f}k"
    return f"{v:.1f}"

def hist_summary(tbl):
    vals = []
    for k, v in tbl.items():
        count = v.value
        mid = (1 << k.value)
        vals.extend([mid] * count)
    tbl.clear()
    if not vals:
        return None
    vals.sort()
    n = len(vals)
    def pct(p): return vals[int(n*p)-1] if n>0 else 0
    return dict(
        n=n,
        avg=sum(vals)/n,
        p50=pct(0.5),
        p90=pct(0.9),
        p95=pct(0.95),
    )

def print_block(title):
    print(f"\n{title}\n" + "─"*42)

last_resp = 0

while True:
    time.sleep(INTERVAL)
    print_block(f"🕒  Metrics Snapshot ({INTERVAL}s)")

    # TCP
    attempts = sum(v.value for v in b["connect_attempt_cnt"].values())
    success = sum(v.value for v in b["connect_success_cnt"].values())
    rate = (success/attempts*100) if attempts else 0
    retrans = sum(v.value for v in b["retrans_count"].values())

    print("[TCP]")
    print(f"  Backend Connects   : {attempts:<5} attempts, {success:<5} successes ({rate:>6.2f}%)")
    print(f"  Retransmissions    : {retrans}")

    # CPU
    cpu = hist_summary(b["sched_delay_us"])
    if cpu:
        print("\n[CPU]")
        print(f"  Sched Delay (µs)   : avg {fmt(cpu['avg']):<6}  p50 {fmt(cpu['p50']):<6}  p90 {fmt(cpu['p90']):<6}  p95 {fmt(cpu['p95']):<6}")
    else:
        print("\n[CPU]\n  Sched Delay (µs)   : –")

    # HTTP
    req = hist_summary(b["proxy_req_forward_us"])
    resp = hist_summary(b["proxy_resp_forward_us"])
    svc = hist_summary(b["http_service_latency_us"])
    total = b["resp_counter"][0].value
    delta = total - last_resp
    last_resp = total
    rps = delta / INTERVAL

    print("\n[HTTP]")
    if req:
        print(f"  Req→Backend Time   : avg {fmt(req['avg'])}µs  p50 {fmt(req['p50'])}  p90 {fmt(req['p90'])}")
    else:
        print(f"  Req→Backend Time   : –")

    if resp:
        print(f"  Resp→Client Time   : avg {fmt(resp['avg'])}µs  p50 {fmt(resp['p50'])}  p90 {fmt(resp['p90'])}")
    else:
        print(f"  Resp→Client Time   : –")

    if svc:
        print(f"  MicroSvc Latency   : avg {fmt(svc['avg'])}µs  p50 {fmt(svc['p50'])}  p90 {fmt(svc['p90'])}")
    else:
        print(f"  MicroSvc Latency   : –")

    print(f"  Throughput (RPS)   : {rps:.2f}  (Δ+{delta} in {INTERVAL}s)")

    # HTTP 状态码统计
    with status_lock:
        if status_counts:
            dist_str = ", ".join([f"{code}={cnt/sum(status_counts.values())*100:.1f}%({cnt})"
                                  for code, cnt in sorted(status_counts.items())])
            print(f"  Status Codes       : {dist_str}")
        else:
            print(f"  Status Codes       : –")
        status_counts.clear()

    print("─"*42)

