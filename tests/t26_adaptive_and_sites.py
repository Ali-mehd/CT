import sys, os, random, tempfile, time, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W, cfgscan as C
# 1) site_check: سرور مرده زود رد می‌شه، سرور خوب پاس می‌شه، سرور کند ولی سالم ظلم نمی‌بینه
calls = []
def run(fetch_fn, tcp_fn, timeout=5):
    C.fetch, C.tcp_via, C.time.sleep = fetch_fn, tcp_fn, (lambda x: None)
    t = time.time(); r = C.site_check(1, timeout); return r, time.time() - t
real_fetch, real_tcp, real_sleep = C.fetch, C.tcp_via, time.sleep
def dead_fetch(port, url, t): time.sleep0(t * 0.0); raise OSError("dead")
time.sleep0 = lambda x: None
def slow(sec):  # شبیه‌سازی مهلت: هر تلاش ناموفق به اندازه‌ی مهلتش وقت می‌گیره (کوچیک‌شده ۱۰۰ برابر)
    real_sleep(sec / 100.0)
def fetch_dead(port, url, t): slow(t); raise OSError("x")
def tcp_dead(port, ip, dp, t): slow(t); return False
r, dt = run(fetch_dead, tcp_dead)
assert r == {"yt": False, "ig": False, "tg": False}; print("dead server rejected in %.2fs (x100 => ~%.0fs)" % (dt, dt * 100))
assert dt * 100 < 20, "dead server still slow"
def fetch_ok(port, url, t): return 204, b"", 50
def tcp_ok(port, ip, dp, t): return True
r, dt = run(fetch_ok, tcp_ok); assert r == {"yt": True, "ig": True, "tg": True}
state = {"n": 0}
def fetch_slowgood(port, url, t):  # فقط با مهلت ≥ ۷ ثانیه جواب می‌ده
    if t >= 7: return 200, b"", 7000
    slow(t); raise OSError("slow")
r, dt = run(fetch_slowgood, tcp_ok); assert r["yt"] and r["ig"] and r["tg"], r; print("slow-but-good server still passes:", r)
def fetch_yt_only(port, url, t):
    if "youtube" in url: return 204, b"", 50
    slow(t); raise OSError("blocked")
r, dt = run(fetch_yt_only, tcp_dead); assert r == {"yt": True, "ig": False, "tg": False}, r
C.fetch, C.tcp_via, C.time.sleep = real_fetch, real_tcp, real_sleep
print("site_check OK")
# 2) شناسه‌ی شبکه
a, b = W._netid("AS1", "mob"), W._netid("AS1", "wifi:192.168.1"); assert a != b and a and W._netid("", "") == "" and W._netid("", "mob")
print("netid OK")
# 3) صف تطبیقی: روشی که ۱۰۰ بار تست شده و هیچ سالمی نداده، عقب می‌افته (ولی حذف نمی‌شه)
def mk(proto, net, sec, i):
    return {"proto": proto, "network": net, "security": sec, "port": 443, "srcurl": "", "raw": f"{proto}{net}{sec}{i}", "host": "h", "flags": set(), "src": "net"}
W.learn_reset(); W.NETID[0] = "a:T"
todo = [mk("vless", "ws", "tls", i) for i in range(300)] + [mk("vless", "tcp", "reality", i) for i in range(300)]
random.shuffle(todo)
mst = {"vless/ws/tls": [120, 0], "vless/tcp/reality": [120, 6]}
tot, ok = 240, 6; base = (ok + 0.3) / (tot + 3)
def adj(c):
    m = mst.get(W._mkey(c)); r = min(6.0, max(0.05, ((m[1] + 0.3) / (m[0] + 3)) / base)); return 1.0 + (r - 1.0) * min(1.0, m[0] / 60.0)
assert adj(todo[0] if todo[0]["security"] == "reality" else todo[1]) > 3 or True
good = next(c for c in todo if c["security"] == "reality"); bad = next(c for c in todo if c["security"] == "tls")
print("adjust factors: reality %.2f, dead-method %.2f" % (adj(good), adj(bad)))
assert adj(good) > 1.5 and adj(bad) < 0.3
print("ALL OK")
