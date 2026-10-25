# آنتی‌ویروس/فایروالِ دستگاه: اتصالِ بسته‌شده توسط سیستم (کد 10013) خرابیِ سرور نیست؛ ثبت می‌شه، دوباره تلاش نمی‌شه، یادگیری/قرنطینه رو خراب نمی‌کنه
import sys, os, tempfile, time, threading, random, socket, errno
os.environ["CFG_DATA"] = tempfile.mkdtemp(); os.environ["CFG_NETPROBE"] = "0"
sys.path.insert(0, '.')
import cfgscan as C, cfgweb as W, cfgtrace as T
mk = lambda ip, port=443: C.static(C.parse(f"vless://00000000-aaaa-bbbb-cccc-000000000000@{ip}:{port}?type=ws&security=tls&sni=a.example.com&path=%2Fx&host=a.example.com#t"))
calls = []
def fake_cc(mode):
    def f(addr, timeout=None):
        calls.append(addr)
        if mode == "av":
            e = OSError(errno.EACCES, "forbidden"); e.winerror = 10013; raise e
        if mode == "refused": raise ConnectionRefusedError(errno.ECONNREFUSED, "refused")
        class S:  # اتصال موفق
            def close(s): pass
        return S()
    return f
real = socket.create_connection
try:
    T.reset(); C.REACH_CACHE.clear(); C.LOCAL_BLOCK.clear()
    # 1) بسته‌شده توسط دستگاه
    socket.create_connection = fake_cc("av")
    c = C.reach(mk("45.1.2.3"), 1); assert not c["reachable"] and "local_block" in c["flags"], c["flags"]
    assert "45.1.2.3" in C.LOCAL_BLOCK
    n = len(calls); c = C.reach(mk("45.1.2.3"), 1); assert "local_block" in c["flags"] and len(calls) == n, "must not reconnect to a locally blocked address"
    assert T.snapshot()["count"].get("conn:10013") == 1
    # 2) رد شدنِ واقعی (سرور بسته): خرابی سرور، نه بلاک محلی؛ و فقط یک بار وصل می‌شه حتی با چند کانفیگِ هم‌آدرس
    socket.create_connection = fake_cc("refused"); calls.clear()
    for _ in range(4):
        c = C.reach(mk("45.9.9.9"), 1); assert not c["reachable"] and "local_block" not in c["flags"]
    assert len(calls) == 1, calls
    # 3) موفق: کش، و شمارش اتصال آنی
    socket.create_connection = fake_cc("ok"); calls.clear()
    for _ in range(3): assert C.reach(mk("45.7.7.7"), 1)["reachable"]
    assert len(calls) == 1
    assert T.snapshot()["count"].get("tcp_instant", 0) >= 1   # اتصالِ جعلی فوری بود
    # 4) ذخیره و بارگذاری
    W.LB_FILE = W.DATA / "localblock.json"; W.save_localblock(); C.LOCAL_BLOCK.clear(); W.load_localblock()
    assert "45.1.2.3" in C.LOCAL_BLOCK
    C.LOCAL_BLOCK["45.1.2.3"] = time.time() - 9 * 86400; W.save_localblock(); assert "45.1.2.3" not in C.LOCAL_BLOCK, "old entries expire"
finally:
    socket.create_connection = real
print("reach(): OK")

# 5) pipeline: آدرس‌های بسته‌شده توسط دستگاه یادگیری و قرنطینه رو خراب نمی‌کنن، شمرده می‌شن و نرخ کم می‌شه
T.reset(); C.REACH_CACHE.clear(); C.LOCAL_BLOCK.clear(); W.AVF[0] = 1.0; W.learn_reset()
links = [f"vless://{i:08d}-aaaa-bbbb-cccc-000000000000@45.{i % 200 + 1}.{i // 200 + 1}.5:443?type=ws&security=tls&sni=a{i}.example.com&path=%2Fx&host=a{i}.example.com#w{i}" for i in range(300)]
def fake_reach(c, t):
    if random.random() < 0.3: c["flags"].add("local_block"); c["reachable"] = False
    else: c["reachable"] = random.random() < 0.7
def fake_live(c, xray, rounds, t, **k): time.sleep(0.002); c["alive"] = random.random() < 0.2; c["sites"] = {}
C.reach, C.live = fake_reach, fake_live
C.fetch_sources = lambda urls, **kw: (list(links), {})
W.find_xray = lambda: "/bin/true"; W.find_singbox = lambda: None
W.disconnect = lambda *a, **k: None; W.refill = lambda *a, **k: None; W.channels_retry = lambda *a, **k: None
W.sites_pick = lambda found, cache: []; W.PREFETCH.update(links=[], stats={}, t=0)
learned = []; real_lr = W.learn_record; W.learn_record = lambda c, kind: (learned.append(("local_block" in c["flags"], kind)), real_lr(c, kind))[1]
th = threading.Thread(target=W.pipeline, args=("balanced", False, False, "off", False), daemon=True); th.start()
t_end = time.time() + 90
while time.time() < t_end and th.is_alive() and W.DIAG.get("local_block", 0) < 45: time.sleep(0.2)  # صبر تا آنتی‌ویروسِ جعلی چند اتصال ببنده (نه تعداد ثابتِ تست)
W.STOP.set(); th.join(30)
lb = W.DIAG.get("local_block", 0)
print("local blocks counted:", lb, "| pace factor:", W.AVF[0], "| learned records:", len(learned))
assert lb >= 25 and W.AVF[0] < 1.0, "should have noticed and slowed down"
assert not any(x[0] for x in learned), "a locally blocked address must never be learned as a dead server"
assert any(e[1] == "local_block" for e in T.snapshot()["events"]) and T.snapshot()["incidents"]
import evolve
ctx = W.evolve_ctx(); assert ctx["av"]["run_diag"] == lb and isinstance(ctx["blocklist_entries"], (dict, type(None)))
print("ALL OK")
