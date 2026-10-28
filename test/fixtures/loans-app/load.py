"""Load script: ~300 fake members create loans, poll them, list their loans."""
import base64, hashlib, hmac, json, os, random, sys, time, threading
import httpx

BASE = os.environ.get("APP", "http://127.0.0.1:8000")
SECRET = os.environ.get("JWT_SECRET", "dev-secret").encode()
MEMBERS = int(os.environ.get("MEMBERS", "300"))
ROUNDS = int(os.environ.get("ROUNDS", "3"))

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jwt(sub):
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64(json.dumps({"sub": sub, "iat": int(time.time())}).encode())
    s = b64(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{s}"

def member(i):
    mid = f"M-{i:05d}"
    c = httpx.Client(base_url=BASE, headers={"Authorization": "Bearer " + jwt(mid)}, timeout=10)
    loans = []
    for _ in range(ROUNDS):
        r = c.post("/loans", json={"bookId": f"BK-{random.randint(1,200):04d}"})
        if r.status_code == 201:
            loans.append(r.json()["id"])
        time.sleep(random.random() * 0.2)
    time.sleep(1)
    for lid in loans:
        c.get(f"/loans/{lid}")   # still 'queued' here
    time.sleep(3.5)  # let notifications settle
    for lid in loans:
        c.get(f"/loans/{lid}")
    c.get(f"/members/{mid}/loans")

def main():
    ths = []
    t0 = time.time()
    for i in range(1, MEMBERS + 1):
        t = threading.Thread(target=member, args=(i,)); t.start(); ths.append(t)
        if i % 30 == 0: time.sleep(0.5)
    for t in ths: t.join()
    print(f"done {MEMBERS} members x {ROUNDS} in {time.time()-t0:.1f}s")

if __name__ == "__main__":
    main()
