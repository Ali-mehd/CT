"""تشخیص فعالیت (cfgact): لاگ و آمار واقعی xray، طبقه‌بندی، هیسترزیس. اگه فایل xray نباشه بخش زنده رد می‌شه."""
import sys, os, time, json, threading, subprocess, socket, tempfile, shutil
sys.path.insert(0, ".")
import cfgact as A

NOW = 1_800_000_000.0
def fl(proto="tcp", host="example.com", port=443, sport=50000, t=NOW): return dict(t=t, proto=proto, host=host, port=port, sport=sport, inb="socks-in")
def rates(up_kbit, dn_kbit, secs=20):
    r = A.Rates(); u = d = 0
    for i in range(secs + 1):
        r.add(u, d, NOW - secs + i); u += int(up_kbit * 1000 / 8); d += int(dn_kbit * 1000 / 8)
    return r

# ۱) لاگ‌های واقعی xray 26.3.27
L1 = "2026/10/25 12:42:51.077072 from 127.0.0.1:44960 accepted http://127.0.0.1:19999/srv.bin [http-in -> proxy-1]"
L2 = "2026/10/25 12:42:51.098768 from tcp:127.0.0.1:34554 accepted tcp:localhost:19999 [socks-in -> proxy-1]"
L3 = "2026/10/25 12:42:51.121598 from 127.0.0.1:55560 accepted tcp:127.0.0.1:19810 [api-in -> api]"
L4 = "2026/10/25 12:43:00.1 from udp:127.0.0.1:61000 accepted udp:stun.l.google.com:19302 [socks-in -> proxy-1]"
L5 = "2026/10/25 12:43:00.2 from 127.0.0.1:50001 accepted tcp:www.instagram.com:443 [http-in >> proxy-1]"
L6 = "2026/10/25 12:43:00.2 from tcp:127.0.0.1:50002 accepted tcp:[2001:db8::1]:443 [socks-in -> proxy-1]"
f = A.parse_access(L1); assert (f["proto"], f["host"], f["port"], f["sport"]) == ("tcp", "127.0.0.1", 19999, 44960), f
f = A.parse_access(L2); assert (f["proto"], f["host"], f["port"], f["sport"]) == ("tcp", "localhost", 19999, 34554), f
assert A.parse_access(L3) is None and A.parse_access("garbage") is None and A.parse_access("") is None
f = A.parse_access(L4); assert (f["proto"], f["host"], f["port"]) == ("udp", "stun.l.google.com", 19302)
f = A.parse_access(L5); assert (f["host"], f["port"]) == ("www.instagram.com", 443)
f = A.parse_access(L6); assert (f["host"], f["port"]) == ("2001:db8::1", 443), f
print("1) real xray access-log lines parse (http URL form, socks, udp, ipv6, api filtered) OK")

# ۲) آمار: خروجی واقعی statsquery (مقدار صفر حذف می‌شه) و فقط proxy-*
S1 = json.dumps({"stat": [{"name": "outbound>>>proxy-1>>>traffic>>>downlink", "value": 6000410}, {"name": "outbound>>>direct>>>traffic>>>uplink"},
                          {"name": "outbound>>>proxy-1>>>traffic>>>uplink", "value": 189}, {"name": "outbound>>>direct>>>traffic>>>downlink", "value": 77}]})
assert A.parse_stats(S1) == (189, 6000410) and A.parse_stats("not json") is None and A.parse_stats('{"stat":[]}') == (0, 0)
r = A.Rates(); r.add(1000, 1000, NOW); r.add(500, 400, NOW + 3)  # ری‌استارتِ xray: شمارنده کم می‌شه ← از نو
assert len(r.s) == 1
r = rates(800, 40); u, d = r.avg(15); assert 700 < u < 900 and 30 < d < 50, (u, d)
print("2) stats parsing + rate math (incl. counter reset) OK")

# ۳) طبقه‌بندی
def C(flows, up, dn, procs=None): return A.classify(flows, rates(up, dn), procs, NOW)[0]
assert C([], 0, 0) == "idle"
assert C([fl(host="news.example.org")], 60, 200) == "normal"
assert C([fl(host="www.instagram.com"), fl(host="scontent.cdninstagram.com", sport=50001)], 80, 900) == "interactive"
assert C([fl(host="149.154.167.51", sport=50010)], 900, 40) == "upload"          # آپلود فایل ۵۵ مگ تلگرام
assert C([fl(host="dl.example.com")], 40, 6000) == "download"
assert C([fl(host="r1.googlevideo.com"), fl(host="r2.googlevideo.com", sport=50003)], 40, 6000) == "interactive"   # ویدیو دانلود فایل نیست
assert C([fl(proto="udp", host="149.154.167.9", port=1400, sport=61000)], 48, 52) == "call"   # تماس: UDP + نرخ دوطرفه‌ی کم
assert C([fl(proto="udp", host="8.8.8.8", port=53, sport=61001)], 1, 1) == "normal"          # DNS تماس نیست
assert C([fl(proto="udp", host="1.1.1.1", port=443, sport=61002)], 300, 4000) != "call"      # QUIC تماس نیست
assert C([fl(proto="udp", host="x", port=40001, sport=61003)], 0, 0, {61003: "whatsapp.exe"}) == "call"
assert C([fl(host="ib.bank-example.ir"), fl(host="dl.example.com", sport=50004)], 900, 40) == "secure"   # حساس از آپلود جلوتره
assert C([fl(host="example.com", sport=50005)], 5, 5, {50005: "keepassxc.exe"}) == "secure"
assert C([fl(proto="udp", host="1.2.3.4", port=3478, sport=61004), fl(host="ib.bank-example.ir", sport=50006)], 48, 52) == "call"  # تماس از حساس جلوتره
print("3) classification: upload/download/call/secure/interactive/normal/idle with priorities OK")

# ۴) هیسترزیس
T = A.Tracker(); t0 = NOW
T.update("idle", now=t0)
for i in range(3): T.update("upload", now=t0 + i)           # کمتر از ۸ ثانیه ← هنوز نه
assert T.act == "idle"
for i in range(3, 12): T.update("upload", now=t0 + i)
assert T.act == "upload"
T.update("normal", now=t0 + 13); T.update("normal", now=t0 + 20)   # شلوغیِ کوتاه عوضش نمی‌کنه
assert T.act == "upload"
T.update("call", now=t0 + 21); T.update("call", now=t0 + 27)       # اولویت بالاتر زود وارد می‌شه (۵ ثانیه)
assert T.act == "call"
for i in range(28, 60): T.update("normal", now=t0 + i)              # خروج از تماس دیرتره (۴۰ ثانیه)
assert T.act == "call" or T.act == "normal"
for i in range(60, 120): T.update("normal", now=t0 + i)
assert T.act == "normal"
print("4) hysteresis: no flapping, high-priority enters fast, call/secure leave slowly OK")

# ۵) Sampler end-to-end روی خطوط
S = A.Sampler(); n = time.time()
S.feed_line(L4.replace("12:43", "12:43")); S.flows[-1]["t"] = n
for i in range(25): S.tick((i * 6000, i * 6500), n - 25 + i)
info = S.tick((25 * 6000, 25 * 6500), n); assert info["act"] in A.ACTS and "fa" in info
print("5) sampler tick returns a displayable state OK")

# ۶) زنده: xray واقعی (اگه موجود باشه)
xr = os.environ.get("CT_XRAY") or "/tmp/xr/xray"
if os.path.exists(xr):
    import http.server, socketserver
    cfg = {"log": {"loglevel": "warning", "access": ""}, "stats": {}, "api": {"tag": "api", "services": ["StatsService"]},
           "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
           "inbounds": [{"tag": "socks-in", "listen": "127.0.0.1", "port": 19818, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
                        {"tag": "http-in", "listen": "127.0.0.1", "port": 19819, "protocol": "http"},
                        {"tag": "api-in", "listen": "127.0.0.1", "port": 19820, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}],
           "outbounds": [{"tag": "proxy-1", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}],
           "routing": {"rules": [{"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}, {"type": "field", "network": "tcp,udp", "outboundTag": "proxy-1"}]}}
    d = tempfile.mkdtemp(); open(d + "/srv.bin", "wb").write(os.urandom(4_000_000))
    class Q(http.server.SimpleHTTPRequestHandler):
        def __init__(s, *a, **k): super().__init__(*a, directory=d, **k)
        def log_message(s, *a): pass
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 19998), Q); threading.Thread(target=srv.serve_forever, daemon=True).start()
    p = subprocess.Popen([xr, "run", "-c", "stdin:"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.stdin.write(json.dumps(cfg).encode()); p.stdin.close()
    S = A.Sampler(); threading.Thread(target=S.reader, args=(p.stdout, lambda: False), daemon=True).start()
    for _ in range(50):
        try: socket.create_connection(("127.0.0.1", 19818), 0.2).close(); break
        except OSError: time.sleep(0.1)
    try:
        t1 = A.query_stats(xr, 19820); assert t1 is not None
        subprocess.run(["curl", "-s", "-x", "http://127.0.0.1:19819", "-o", "/dev/null", "http://127.0.0.1:19998/srv.bin"], timeout=20)
        subprocess.run(["curl", "-s", "--socks5-hostname", "127.0.0.1:19818", "-o", "/dev/null", "http://localhost:19998/srv.bin"], timeout=20)
        time.sleep(0.5); t2 = A.query_stats(xr, 19820)
        assert t2 and t2[1] - t1[1] >= 7_000_000, (t1, t2)
        assert any(f["port"] == 19998 for f in list(S.flows)), list(S.flows)
        assert not any(f["port"] == 19820 for f in list(S.flows)), "API queries must not appear as user traffic"
        print("6) REAL xray: stats API bytes + access-log flows parsed, API traffic filtered OK")
    finally:
        p.kill(); srv.shutdown(); shutil.rmtree(d, ignore_errors=True)
else:
    print("6) (skipped: no xray binary)")
print("ALL OK")
