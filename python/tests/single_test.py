#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time

SERVER_HOST = "127.0.0.1"   # 服务器地址
SERVER_PORT = 8080          # 服务器监听端口
INTERVAL = 2                # 每次连接间隔秒数

def slow_connect_test():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # 设置超时
            sock.connect((SERVER_HOST, SERVER_PORT))
            print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")
            sock.close()
        except Exception as e:
            print(f"Connection failed: {e}")
        time.sleep(INTERVAL)

if __name__ == "__main__":
    slow_connect_test()
