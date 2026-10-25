# ردپا و گزارش تکامل: ثبت رویداد/خطا/زمان‌سنجی، خلاصه‌ی خودکار، علت شکست هر تست، اجرای واقعی pipeline، و نبودن آدرس توی گزارش
import sys, os, tempfile, time, threading, random, socket, json
os.environ["CFG_DATA"] = tempfile.mkdtemp(); os.environ["CFG_NETPROBE"] = "0"
sys.path.insert(0, '.')
import cfgtrace as T, cfgweb as W, cfgscan as C, evolve

# ---- cfgtrace پایه
T.reset()
for i in range(500): T.evt("x", f"e{i}")
s = T.snapshot(); assert len(s["events"]) == 120 and s["events"][-1][2] == "e499"
for i in range(1000): T.perf("live_ok_s", i / 1000.0)
p = T.snapshot()["perf"]["live_ok_s"]; assert p["n"] == 1000 and 0.4 < p["p50"] < 0.6 and p["p90"] > 0.8 and p["max"] == 0.999, p
for _ in range(3): T.err("fetch", socket.timeout("slow"))
T.err("fetch", ValueError("bad")); e = T.snapshot()["errors"]; assert e["fetch:TimeoutError"][0] == 3 and e["fetch:ValueError"][0] == 1
T.run_begin(level=1); T.run_mark("first_alive"); time.sleep(0.05); T.run_mark("first_alive"); T.run_end("done"); T.run_end("again")
r = T.snapshot()["runs"][-1]; assert r["end"]["why"] == "done" and list(r["marks"]) == ["first_alive"] and r["marks"]["first_alive"] < 0.04
for i in range(20): T.incident("k", n=i)
assert len(T.snapshot()["incidents"]) == 8
print("cfgtrace basics: OK")

# ---- hints: گلوگاه واقعی، علت شکست، ترمز CPU
T.reset()
for _ in range(60): T.perf("live_dead_s", 4.8); T.perf("slot_wait_s", 4.0); T.perf("pace_wait_s", 0.02)
for k, n in (("test_total", 100), ("why:core_port", 20), ("why:timeout", 40), ("why:no_reach", 30), ("why:ok", 10)): T.count(k, n)
T.run_begin(); T.run_end("time is up")
h = T.hints(T.snapshot(), {"loadguard": {"on": True, "min_f": 0.3, "lag_s": 0.5, "duty": 0.6}})
txt = " | ".join(x[1] for x in h); print("\n".join(f"  [{l}] {m[:110]}" for l, m in h))
assert h[0][0] == "high" and "گلوگاه" in txt and "core_port" in txt and "ترمز CPU" in txt and "timeout" in txt
assert T.hints({}, None) == [], "empty trace must give no hints"

# ---- cfgscan.live: علت شکست هر تست
class FakeProc:
    def __init__(self, dead): self._d = dead; self.stdin = type("S", (), {"write": lambda s, b: None, "close": lambda s: None})()
    def poll(self): return 1 if self._d else None
    def terminate(self): pass
    def wait(self, t=None): pass
    def kill(self): pass
c0 = dict(W.cfgscan.parse("vless://00000000-aaaa-bbbb-cccc-000000000000@45.1.2.3:443?type=tcp&security=reality&pbk=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE&sni=a.example.com&sid=ab&flow=xtls-rprx-vision&fp=chrome#t"))
ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(5); open_port = ls.getsockname()[1]
def run_live(dead, fetch_exc=None, port=None, status=204):
    c = dict(c0); c["flags"] = set()
    C.subprocess.Popen = lambda *a, **k: FakeProc(dead)
    C.free_port = lambda: port or open_port
    def f(port_, url, t):
        if fetch_exc: raise fetch_exc
        return status, b"", 20
    real_f, real_s = C.fetch, time.sleep
    C.fetch = f; time.sleep = lambda x: None
    try: C.live(c, "/bin/true", 1, 1)
    finally: C.fetch, time.sleep = real_f, real_s
    return c
assert run_live(True, ConnectionError("x"), port=1)["fail"] == "core_exit"      # هسته بلافاصله مرد: ریشه همینه، نه خطای بعدیِ اتصال
assert run_live(False, socket.timeout())["fail"] == "timeout"
assert run_live(False, ConnectionError("connect"))["fail"] == "tunnel_refused"
assert run_live(False, ConnectionResetError())["fail"] == "reset"
assert run_live(False, status=403)["fail"] == "http_403"
ok = run_live(False); assert ok["alive"] and "fail" not in ok
print("live() failure reasons: OK")

# ---- اجرای واقعی pipeline با قطعه‌های جعلی: نقاط زمانی، علت‌ها و زمان‌سنجی‌ها ثبت می‌شن
T.reset(); random.seed(5)
links = [f"vless://{i:08d}-aaaa-bbbb-cccc-000000000000@45.{i % 200 + 1}.{i // 200 + 1}.5:443?type=ws&security=tls&sni=a{i}.example.com&path=%2Fx&host=a{i}.example.com#w{i}" for i in range(300)]
def fake_reach(c, t): c["reachable"] = random.random() < 0.6
def fake_live(c, xray, rounds, t, **k):
    time.sleep(0.003); c["alive"] = random.random() < 0.1; c["sites"] = {}
    if not c["alive"]: c["fail"] = random.choice(["timeout", "tunnel_refused"])
C.reach, C.live = fake_reach, fake_live
C.fetch_sources = lambda urls, **kw: (list(links), {})
W.find_xray = lambda: "/bin/true"; W.find_singbox = lambda: None
W.disconnect = lambda *a, **k: None; W.refill = lambda *a, **k: None; W.channels_retry = lambda *a, **k: None
W.sites_pick = lambda found, cache: []; W.PREFETCH.update(links=[], stats={}, t=0)
th = threading.Thread(target=W.pipeline, args=("balanced", False, False, "off", False), daemon=True); th.start()
t_end = time.time() + 40
while time.time() < t_end and (T.snapshot()["count"].get("test_total") or 0) < 250: time.sleep(0.2)
W.STOP.set(); th.join(30)
s = T.snapshot(); r = s["runs"][0]
print("run marks:", r["marks"], "| end:", r["end"], "| counts:", {k: v for k, v in s["count"].items() if k.startswith("why:")})
assert {"fetch_done", "first_reach", "first_alive"} <= set(r["marks"]), r["marks"]
assert s["count"]["test_total"] >= 250 and s["count"].get("why:timeout") and s["count"].get("why:no_reach") and s["count"].get("why:ok")
for k in ("reach_s", "live_ok_s", "live_dead_s", "slot_wait_s", "pace_wait_s"): assert s["perf"][k]["n"] > 10, k
assert any(e[1] == "search" for e in s["events"])

# ---- گزارش کامل: شامل trace/hints، و هیچ آدرسی توش نیست
T.evt("probe", "اتصال به 203.0.113.9:443 و https://evil.example/path?token=abcdefghijklmnopqrstuvwxyz0123456789 و user@mail.com")
T.incident("x", host="198.51.100.7", detail="vless://aaaaaaaa-aaaa-bbbb-cccc-000000000000@1.2.3.4:443")
ctx = W.evolve_ctx(); assert "trace" in ctx and "hints" in ctx and "loadguard" in ctx
rid, plain = evolve.make_report(ctx, plain=True)
for bad in ("203.0.113.9", "evil.example", "198.51.100.7", "user@mail.com", "abcdefghijklmnopqrstuvwxyz0123456789", "1.2.3.4"):
    assert bad not in plain, bad
rid2, sealed = evolve.make_report(ctx); back = evolve.open_report(sealed); assert back["ctx"]["trace"]["events"] and "hints" in back["ctx"]
print("report: %d bytes plain, sealed ok, no addresses leaked" % len(plain))
print("ALL OK")
