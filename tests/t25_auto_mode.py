"""فوق هوشمند: xray واقعی با API/لاگ، سیاست انتقال کند، نگه‌داشتن وسط تماس/کار حساس، قفل سرور، ساعت شبیه‌سازی‌شده."""
import sys, os, tempfile, json, time, threading, subprocess, socket, types
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W, cfgact as A, cfgscan, cfgforge, cfgcall

def mk(h, **kw):
    c = {"host": h, "port": 443, "proto": "vless", "network": "ws", "security": "tls", "flow": "", "raw": f"vless://{h}:443", "ip": "",
         "alive": True, "flags": set(), "success": 1.0, "lat": 100, "sites": dict(yt=1, ig=1, tg=1), "site_t": time.time(), "verified_at": time.time()}
    c.update(kw); return c

# ۱) پروفایل پیش‌فرض و ثبت‌شده
assert "auto" in cfgforge.PROFILES and cfgforge.PROFILES["auto"]["mux"] is False and W.CUR[0] == "auto" and W.ROUNDS["auto"] == 3
print("1) 'auto' profile exists (no mux), is the default OK")

# ۲) xray واقعی: start_xray با پروفایل auto ← API و لاگ دسترسی کار می‌کنه، بدون ریختن چیزی روی دیسک
xr = os.environ.get("CT_XRAY") or "/tmp/xr/xray"
if os.path.exists(xr):
    W.find_xray = lambda: xr
    link = "vless://11111111-1111-1111-1111-111111111111@10.255.255.1:443?type=ws&security=tls&sni=h.example.com&path=%2Fws&host=h.example.com#t"
    c = cfgscan.parse(link); c.setdefault("flags", set())
    W.SOCKS, W.HTTP = 19908, 19909
    sel = W.start_xray([c], "auto")
    try:
        assert W.APIPORT[0] > 0 and W.XRAY_PROC.stdout is not None
        t = A.query_stats(xr, W.APIPORT[0]); assert t is not None, "stats API must answer"
        subprocess.run(["curl", "-s", "-m", "3", "--socks5-hostname", f"127.0.0.1:{W.SOCKS}", "-o", "/dev/null", "http://stun.example.org:3478/"], timeout=8)
        time.sleep(0.6)
        assert any(f["host"] == "stun.example.org" for f in list(W.ACT.flows)), list(W.ACT.flows)[-3:]
        assert not any(f["port"] == W.APIPORT[0] for f in list(W.ACT.flows))
        # پروفایل غیر auto: هیچ API/لاگی نباید باشه
        # نردبان اتصال اول «plain» رو امتحان می‌کنه؛ این حالت هم باید API داشته باشه (باگ واقعیِ گزارش ۲۳:۲۷)
        W.start_xray([c], "auto", True); assert W.APIPORT[0] > 0 and A.query_stats(xr, W.APIPORT[0]) is not None
        W.start_xray([c], "speed"); assert W.APIPORT[0] == 0 and W.XRAY_PROC.stdout is None
        print("2) REAL xray via start_xray('auto'): stats API answers, access log feeds activity, other profiles unchanged OK")
    finally:
        W.disconnect(silent=True)
        assert W.APIPORT[0] == 0 and not list(W.ACT.flows) and W.S.get("act") is None
else:
    print("2) (skipped: no xray binary)")

# ۳) انتقال لاک‌پشتی: سرور واضحاً سریع‌تر ← جابه‌جایی؛ سرور نه چندان بهتر ← ماندن
def setup():
    W.GEN[0] += 1; W.STOP.clear(); W.MODE[0] = "stable"; W.CUR[0] = "auto"
    W.S.update(stage="connected", note="", warn="")
    act = mk("50.0.0.1"); W.POOL.update(active=[act], standby=[mk("50.0.0.2"), mk("50.0.0.3"), mk("50.0.0.4")], bench=[], switches=0)
    W.AUTO.update(cool=0.0, tp={}, crawl_t0=0.0, call_poor=0, call_mos=0.0)
    W.HOLD_UNTIL[0] = 0
    started = []
    W.start_xray = lambda sel, profile, plain=False: (started.append(sel[0]["host"]), sel)[1]
    W.probe_retry = lambda *a, **k: 90.0
    W.set_active = lambda sel, ms=None: W.POOL.update(active=list(sel))
    W.save_good = lambda sel: None; W.sw_mark = lambda r: None
    return act, started
act, started = setup()
W.check_many = lambda cs, *a, **k: [dict(c, kbps_up=(9000 if c["host"] == "50.0.0.3" else 700)) for c in cs]
W._tp_switch(W.GEN[0], "auto", "upload", 300)
assert started == ["50.0.0.3"] and W.POOL["active"][0]["host"] == "50.0.0.3", (started, W.S["note"])
act, started = setup()
W.check_many = lambda cs, *a, **k: [dict(c, kbps_up=500) for c in cs]  # هیچ‌کدوم ۲ برابر فعلی (۳۰۰) + ۱۵۰۰ نیست
W._tp_switch(W.GEN[0], "auto", "upload", 300)
assert not started and W.POOL["active"][0] is act and "پیدا نشد" in W.S["note"]
act, started = setup()
W.check_many = lambda cs, *a, **k: [dict(c, kbps=9000) for c in cs]
W._tp_switch(W.GEN[0], "auto", "download", 800)
assert started, "download crawl also switches when a much faster server exists"
print("3) crawling upload/download: switches only to a server clearly faster by REAL measurement, else stays OK")

# ۴) قفل سرور (mode=off): هیچ جابه‌جایی‌ای
act, started = setup(); W.MODE[0] = "off"
W.check_many = lambda cs, *a, **k: [dict(c, kbps_up=9000) for c in cs]
assert W._auto_switch(W.GEN[0], "auto", W.POOL["standby"][0], "x") is False and not started
print("4) locked server (mode=off): auto never switches OK")

# ۵) سیاست: فقط آپلود/دانلودِ کند بعد از ۴۰ ثانیه سنجش راه می‌اندازه؛ تماس و کار حساس هرگز
def pol(act_name, rate_kbit, crawl_age, since=30):
    setup(); W.ACT.reset()
    r = W.ACT.rates; t = time.time()
    u = d = 0
    for i in range(25):
        r.add(u, d, t - 24 + i)
        if act_name == "upload": u += int(rate_kbit * 125); d += 50
        else: d += int(rate_kbit * 125); u += 50
    calls = []
    W._tp_switch = lambda *a, **k: calls.append(a[2])
    W.AUTO["crawl_t0"] = time.time() - crawl_age if crawl_age else 0.0
    W._auto_policy(W.GEN[0], "auto", {"act": act_name, "since": since})
    time.sleep(0.05); return calls
assert pol("upload", 300, 50) == ["upload"]                 # لاک‌پشتی + ۵۰ ثانیه ← سنجش
assert pol("upload", 300, 10) == []                         # هنوز زوده
assert pol("upload", 3000, 50) == []                        # سرعت خوبه
assert pol("download", 900, 50) == ["download"]
assert pol("call", 300, 50) == [] and pol("secure", 300, 50) == [] and pol("normal", 10, 50) == []
print("5) policy: slow bulk transfer -> measure; never for call/secure/normal OK")

# ۶) ناظر با ساعت شبیه‌سازی‌شده
class FakeTime:
    def __init__(s): s.t = 1_800_000_000.0
    def time(s): return s.t
    def sleep(s, x): s.t += max(x, 0.01); time.sleep(0)
    def __getattr__(s, k): return getattr(time, k)
def run_sup(act_name, probes, rate_kbit, seconds, link=None):
    act, started = setup(); W.ACT.reset(); W.APIPORT[0] = 1
    ft = FakeTime(); W.time = ft
    W.ACT.tracker.act = act_name
    r = W.ACT.rates; u = d = 0
    for i in range(10): r.add(u, d, ft.t - 9 + i); u += int(rate_kbit * 125); d += int(rate_kbit * 125)
    pr = iter(probes); last = [None]
    def pro(*a, **k):
        try: last[0] = next(pr)
        except StopIteration: pass
        return last[0]
    W.probe_robust = pro; W.probe = pro
    W.net_up = lambda: True; W.calm_ok = lambda: True; W.server_cut_confirmed = lambda: False
    W.refresh_standby = lambda gen: None; W.upgrade_check = lambda *a: None
    if link: W.link_state = lambda h, f: link
    fo = []; W.failover = lambda gen, profile, sysproxy, mode: (fo.append(ft.t), W.S.update(stage="idle"))
    W.XRAY_PROC = types.SimpleNamespace(poll=lambda: None)
    W.RUNNING[0] = 0
    g = W.GEN[0]
    th = threading.Thread(target=W.supervisor, args=(g, "auto", True, "stable"), daemon=True); th.start()
    t0 = ft.t
    for _ in range(400):
        time.sleep(0.005)
        if ft.t - t0 > seconds or fo: break
    W.GEN[0] += 1; th.join(2); W.time = time
    return fo
real_link = W.link_state
# الف) وسط آپلودِ پرحجم، پراب‌ها (پشت صفِ آپلود) بی‌جواب می‌مونن ولی ترافیک رد می‌شه ← «قطع» نیست
assert run_sup("upload", [None] * 60, 600, 120) == []
# ب) بی‌کار و واقعاً قطع (ترافیکی هم نیست) ← جابه‌جایی بعد از ۵ خطا
fo = run_sup("idle", [None] * 60, 0, 120); assert len(fo) == 1
# پ) وسط تماس، پراب‌ها نوسان‌دار (jittery) ← هیچ جابه‌جایی‌ای، هر چقدر طول بکشه
assert run_sup("call", [100] * 400, 40, 600, link="jittery") == []
assert run_sup("secure", [100] * 400, 40, 600, link="jittery") == []
# ت) نوسان پیوسته در گشت‌وگذار ← بعد از ~۴۰ ثانیه؛ در حالت عادی بعد از ~۷۵ ثانیه؛ ولی نه زودتر از ۹۰ ثانیه‌ی بعد از آخرین جابه‌جایی
fo = run_sup("interactive", [100] * 600, 40, 300, link="jittery"); assert len(fo) == 1
fo = run_sup("normal", [100] * 600, 40, 300, link="jittery"); assert len(fo) == 1
# ث) وسط آپلود، نوسان به‌تنهایی جابه‌جایی نمی‌سازه
assert run_sup("upload", [100] * 600, 600, 400, link="jittery") == []
W.link_state = real_link
print("6) supervisor: bulk transfer ≠ cut, call/secure hold through jitter, browsing reacts to sustained jitter OK")

# ۷) پیام هشدار «تا قطعِ کامل عوض نمی‌شه» دیگه در فوق هوشمند نمیاد و با سیاست واقعی می‌خونه
src = open("cfgweb.py", encoding="utf-8").read()
assert "وسط انتقال حجیم طبیعیه" in src and "وسط {'تماس' if act == 'call' else 'کار حساس'}" in src
print("7) warning texts match the real policy OK")
# ۸) زنجیره‌ی کامل با xray واقعی و ترافیک واقعی: آپلودِ پیوسته ← auto_watch وضعیت «upload» رو نشون می‌ده و شمارنده‌ها پر می‌شن
if os.path.exists(xr):
    import http.server, socketserver
    class Sink(http.server.BaseHTTPRequestHandler):
        def do_POST(s):
            n = int(s.headers.get("Content-Length", 0))
            while n > 0:
                n -= len(s.rfile.read(min(65536, n)))
            s.send_response(200); s.end_headers(); s.wfile.write(b"ok")
        def log_message(s, *a): pass
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 19997), Sink); threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg = {"log": {"loglevel": "warning", "access": ""}, "stats": {}, "api": {"tag": "api", "services": ["StatsService"]},
           "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
           "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 19938, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
                        {"tag": "api-in", "listen": "127.0.0.1", "port": 19940, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}],
           "outbounds": [{"tag": "proxy-1", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
           "routing": {"rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-1"}]}}
    p = subprocess.Popen([xr, "run", "-c", "stdin:"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.stdin.write(json.dumps(cfg).encode()); p.stdin.close()
    setup(); W.ACT.reset(); W.XRAY_PROC, W.APIPORT[0], W.SOCKS = p, 19940, 19938
    W.find_xray = lambda: xr
    threading.Thread(target=W.ACT.reader, args=(p.stdout, lambda: p is not W.XRAY_PROC), daemon=True).start()
    for _ in range(50):
        try: socket.create_connection(("127.0.0.1", 19938), 0.2).close(); break
        except OSError: time.sleep(0.1)
    open("/tmp/up.bin", "wb").write(os.urandom(2_500_000))
    g = W.GEN[0]
    th = threading.Thread(target=W.auto_watch, args=(g, "auto", True), daemon=True); th.start()
    cu = subprocess.Popen(["curl", "-s", "--socks5-hostname", "127.0.0.1:19938", "--limit-rate", "100k", "-X", "POST", "--data-binary", "@/tmp/up.bin",
                           "-o", "/dev/null", "http://127.0.0.1:19997/up"])
    try:
        seen = None
        for _ in range(60):
            time.sleep(0.5)
            a = W.S.get("act")
            if a and a["act"] == "upload": seen = a; break
        assert seen, (W.S.get("act"), W.AUTO["diag"], list(W.AUTO["log"])[-3:])
        assert W.AUTO["diag"]["stats_ok"] >= 3 and W.AUTO["diag"]["stats_fail"] == 0 and not W.AUTO["diag"]["err"], W.AUTO["diag"]
        assert any("آپلود" in m for _, m in W.AUTO["log"]), list(W.AUTO["log"])
        print("8) REAL chain (xray stats + log -> auto_watch): a sustained upload is shown as 'upload' with live KB/s OK")
    finally:
        W.GEN[0] += 1; cu.kill(); p.kill(); srv.shutdown(); th.join(5)
else:
    print("8) (skipped: no xray binary)")
print("ALL OK")
