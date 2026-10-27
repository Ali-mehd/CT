"""شمارنده‌ی مصرف اینترنت + سقف روزانه، تشخیص سریع تغییر شبکه، همگام‌سازی لحظه‌ای صفحه (long-poll)، بخش‌های تازه‌ی گزارش."""
import sys, os, tempfile, json, time, threading, http.client, types
d0 = tempfile.mkdtemp(); os.environ["CFG_DATA"] = d0; sys.path.insert(0, ".")
import cfgdata as D, cfgweb as W, cfgscan

# ۱) شمارنده: دسته‌ها، امروز، ذخیره و بارگذاری
D.TOTAL.update({c: 0 for c in D.CATS}); D.DAY.clear()
D.add(2_000_000, "sources"); D.add(500_000); D.add(300_000, "speed"); D.add(1_000_000, "user")
with D.cat("probe"): D.add(10_000)
t = D.today(); assert t["sources"] == 2_000_000 and t["scan"] == 500_000 and t["probe"] == 10_000 and t["total"] == 2_810_000, t  # ترافیک کاربر جزو مصرف برنامه نیست
D.add(-5); D.add("x"); D.add(0)
pth = os.path.join(d0, "data.json"); D.load(pth); D.save(True)
D.DAY.clear(); D.load(pth); assert D.today()["sources"] == 2_000_000
print("1) data meter: categories, user traffic excluded from app usage, persists across restart OK")

# ۲) شمارش واقعی fetch (SOCKS محلی ساختگی)
class FakeSocks(threading.Thread):
    def __init__(s):
        super().__init__(daemon=True); import socket; s.l = socket.socket(); s.l.bind(("127.0.0.1", 0)); s.l.listen(5); s.port = s.l.getsockname()[1]
    def run(s):
        while True:
            try: c, _ = s.l.accept()
            except OSError: return
            threading.Thread(target=s.h, args=(c,), daemon=True).start()
    def h(s, c):
        try:
            c.recv(3); c.sendall(b"\x05\x00"); c.recv(512); c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            c.recv(2048); c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 4000\r\nConnection: close\r\n\r\n" + b"x" * 4000)
        finally: c.close()
fs = FakeSocks(); fs.start()
b0 = D.today().get("scan", 0)
st, body, _ = cfgscan.fetch(fs.port, "http://example.org/x", 3)
assert st == 200 and len(body) == 4000 and D.today()["scan"] - b0 >= 4400, D.today()
print("2) cfgscan.fetch counts real response bytes OK")

# ۳) سقف روزانه: پیش‌فرض نت همراه ۱۵۰، مودم نامحدود؛ پرشدن سقف ← کارهای پس‌زمینه ساکت
W.CUR[0] = "auto"; W.CALL[0] = False; W.ACT.reset()
W.net_is_mobile = lambda: True
W.load_settings = lambda: {}
assert W.data_budget_mb() == 150
W.net_is_mobile = lambda: False
assert W.data_budget_mb() == 0 and not W.data_saver()
W.load_settings = lambda: {"data_mb": 3, "data_mb_user": True}
assert W.data_budget_mb() == 3
D.DAY.clear(); D.add(2_000_000); assert not W.data_saver() and not W.heavy_quiet()
D.add(1_500_000); assert W.data_saver() and W.heavy_quiet() and not W.bg_quiet() and W.data_view()["saver"]
W.load_settings = lambda: {"data_mb": 0, "data_mb_user": True}
assert not W.data_saver() and not W.heavy_quiet()                    # ۰ = نامحدود
print("3) daily budget: default 150MB on mobile / unlimited otherwise, background goes quiet when exhausted OK")

# ۴) تغییر شبکه: دو نمونه‌ی پشت‌سرهم لازمه؛ نمونه‌ی گذرا نادیده؛ واکنش بسته به مرحله
seq = iter(["wifi:192.168.1#1", "wifi:192.168.1#1", "mob#7", "wifi:192.168.1#1", "wifi:192.168.1#1", "mob#9", "mob#9", "mob#9", "mob#9"] + ["mob#9"] * 50)
W.netprobe = types.SimpleNamespace(net_fp=lambda: next(seq, "mob#9"), net_kind=lambda: "mob")
ch = []
W.on_net_change = lambda old, new: ch.append((old, new))
real_sleep = time.sleep; W.time.sleep = lambda x: real_sleep(0.002)
th = threading.Thread(target=W.net_watch, daemon=True); th.start(); real_sleep(0.4)
W.time.sleep = real_sleep
assert ch == [("wifi:192.168.1#1", "mob#9")], ch
print("4a) network change: needs 2 consecutive samples (≈6 s), a one-sample glitch is ignored OK")

import cfgtrace
W.S.update(stage="running", note="")
restarts = []
W.restart_pipeline = lambda why: restarts.append(why) or True
W.NETP["net"] = {"kind": "wifi"}; W.NETID[0] = "x"
real_oc = None
import importlib
src = open("cfgweb.py", encoding="utf-8").read()
ns = {}
# on_net_change اصلی رو دوباره بگیر (بالا با نسخه‌ی ثبت‌کننده عوض شد)
exec_globals = W.__dict__
exec(compile(src[src.index("def on_net_change(old, new):"):src.index("def net_watch():")], "oc", "exec"), exec_globals)
W.reprobe_net = lambda: None; W.refresh_standby = lambda gen: None; W.sites_guard = lambda *a: None
W.on_net_change("wifi:1#1", "mob#2")
assert restarts and "وسط جستجو" in restarts[0] and W.NETID[0] == "" and W.S["netchg"]["to"] == "نت همراه", (restarts, W.S.get("netchg"))
restarts.clear(); W.S.update(stage="connected"); W.probe = lambda t=3.0: None
W.on_net_change("mob#2", "wifi:1#3")
assert restarts and "جواب نداد" in restarts[0]
restarts.clear(); W.probe = lambda t=3.0: 80.0
W.on_net_change("wifi:1#3", "mob#4")
assert not restarts and "جواب می‌ده" in W.S["note"]
assert W.NETCHG["n"] == 3 and len(W.NETCHG["log"]) == 3
print("4b) network change reaction: restart search mid-search; connected -> probe, restart only if server fails OK")

# ۵) صفحه: long-poll
import http.server, socketserver
W.TOKEN = "tok"; W.S["stage"] = "idle"
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), W.H); port = srv.server_address[1]
W.PORT = port
threading.Thread(target=srv.serve_forever, daemon=True).start()
def get(path):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=20); c.request("GET", path, headers={"X-T": "tok"}); r = c.getresponse(); b = r.read(); return r.status, b
t0 = time.time(); st_, b = get("/api/state"); j = json.loads(b); h = j["_h"]
assert st_ == 200 and h and time.time() - t0 < 1
t0 = time.time(); st_, b = get("/api/state?since=zzz"); assert json.loads(b)["_h"] == h and time.time() - t0 < 1       # هش متفاوت: همان لحظه
res = []
def waiter():
    t = time.time(); st2, b2 = get("/api/state?since=" + h); res.append((time.time() - t, json.loads(b2)["_h"]))
w = threading.Thread(target=waiter); w.start(); time.sleep(1.0)
W.S["msg"] = "تغییر!"; w.join(15)
assert res and 0.9 < res[0][0] < 3.0 and res[0][1] != h, res                  # تا تغییر صبر کرد و بعد فوراً جواب داد (نه ۱٫۵ ثانیه‌ی ثابت)
print("5) long-poll: instant on difference, waits for a change, answers within ~0.2s of it OK")

# ۶) گزارش: بخش‌های تازه
W.SERIES.append({"t": 1, "stage": "idle"}); 
ctx = W.evolve_ctx()
for k in ("summary", "data", "net_changes", "search_now", "threads", "ui_sync", "effective", "series", "auto", "trace"):
    assert k in ctx, k
assert ctx["data"]["today"]["total"] > 0 and ctx["net_changes"]["n"] == 3 and "http_state" in ctx["ui_sync"], ctx["ui_sync"].keys()
assert isinstance(ctx["threads"], dict) and ctx["threads"]
json.dumps(ctx, default=str)
if W._ev:
    rid, text = W._ev.make_report(ctx, plain=True)
    assert '"data"' in text and '"net_changes"' in text and "series" in text
print("6) report: summary/data/net_changes/threads/ui_sync/effective/series are present and serializable OK")
# ۷) نت همراه: دانلودِ سنگین موقع شروع برنامه وقتی فهرستِ تازه‌ی کافی هست تکرار نمی‌شه
from pathlib import Path
W.DATA = Path(d0); (W.DATA / "cache.txt").write_text("vless://x\n" * 60); (W.DATA / "blocklist.txt").write_text("1.1.1.0/24\n")
calls = []
W.cfgscan.fetch_sources = lambda *a, **k: (calls.append("sources"), ([], {}))[1]
W.cfgscan.safe_opener = lambda *a, **k: (calls.append("block"), (_ for _ in ()).throw(OSError("offline")))[0]
W.load_settings = lambda: {}; W.net_is_mobile = lambda: True
W.startup_refresh()
assert not calls, calls
W.update_block(True); assert not calls, calls                       # فهرست سیاهِ تازه هست ← دانلود نمی‌شه
W.net_is_mobile = lambda: False
W.update_block(True); assert "block" in calls, calls                # روی مودم: همون رفتار قبلی (دانلود)
print("7) mobile data saver: startup source/blocklist downloads are skipped while a fresh copy exists OK")
print("ALL OK")
