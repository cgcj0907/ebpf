# test_tcprtt_trigger.py
import requests
import threading
import time
import json

URL = "http://127.0.0.1:8080/echo"
THREADS = 5      # 并发线程数
REQUESTS = 20    # 每个线程请求次数
SLEEP = 0.2      # 每次请求间隔秒

def worker(thread_id):
    for i in range(REQUESTS):
        payload = {"thread": thread_id, "seq": i, "msg": "hello tcprtt"}
        try:
            r = requests.post(URL, json=payload, timeout=2)
            print(f"[Thread {thread_id}][{i}] -> {r.status_code}")
        except Exception as e:
            print(f"[Thread {thread_id}][{i}] ERROR: {e}")
        time.sleep(SLEEP)

threads = []
for t in range(THREADS):
    th = threading.Thread(target=worker, args=(t,))
    threads.append(th)
    th.start()

for th in threads:
    th.join()

print("All requests done.")
