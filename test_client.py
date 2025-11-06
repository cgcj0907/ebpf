import requests, time, threading

URL = "http://127.0.0.1:8080/"
N = 30

def worker():
    for i in range(N):
        try:
            r = requests.get(URL, timeout=2)
            print(f"[{i}] -> {r.status_code}")
        except Exception as e:
            print(f"[{i}] ERROR {e}")

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()

