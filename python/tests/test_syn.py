from scapy.all import IP, TCP, send

TARGET_IP = "117.72.198.106"
TARGET_PORT = 8080
COUNT = 5

for i in range(COUNT):
    # 构造 SYN 包
    ip = IP(dst=TARGET_IP)
    syn = TCP(dport=TARGET_PORT, flags="S", seq=1000 + i)
    packet = ip / syn
    send(packet, verbose=True)
    print(f"[{i}] Sent SYN to {TARGET_IP}:{TARGET_PORT}")
