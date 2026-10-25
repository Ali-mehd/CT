# حالت «آپلود»: سنجش واقعیِ آپلود از راه SOCKS5 (با سرور و پراکسی جعلیِ محلی، بدون اینترنت)، رتبه‌بندی، و اتصال به بقیه‌ی منطق
import sys, os, socket, struct, threading, time, tempfile
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgscan as C, cfgweb as W, cfgforge

def rd(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x: raise ConnectionError
        b += x
    return b

def up_server(rate_kBps, status=b"200 OK"):
    """سرور آپلود جعلی: بدنه رو با سرعت محدود می‌خونه (rate_kBps کیلوبایت/ثانیه)، بعد جواب می‌ده"""
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(16)
    def handle(c):
        try:
            c.settimeout(10)
            buf = b""
            while True:
                while b"\r\n\r\n" not in buf:
                    x = c.recv(65536)
                    if not x: return
                    buf += x
                head, _, buf = buf.partition(b"\r\n\r\n")
                n = int([l for l in head.split(b"\r\n") if l.lower().startswith(b"content-length")][0].split(b":")[1])
                got = len(buf); time.sleep(got / (rate_kBps * 1000.0)); buf = b""
                while got < n:
                    x = c.recv(min(65536, n - got)); 
                    if not x: return
                    got += len(x); time.sleep(len(x) / (rate_kBps * 1000.0))
                c.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length: 2\r\n\r\nok")
        except Exception: pass
        finally: c.close()
    def loop():
        while True:
            try: c, _ = ls.accept()
            except OSError: return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1], ls

def socks_proxy():
    """SOCKS5 جعلی: هر مقصدی رو به سرور محلی هدایت می‌کنه"""
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(16)
    target = [None]
    def handle(c):
        try:
            rd(c, 3); c.sendall(b"\x05\x00")
            h = rd(c, 4); assert h[3] == 3
            n = rd(c, 1)[0]; rd(c, n + 2)
            u = socket.create_connection(("127.0.0.1", target[0]), 5)
            c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            def pump(a, b):
                try:
                    while True:
                        x = a.recv(65536)
                        if not x: break
                        b.sendall(x)
                except Exception: pass
                finally:
                    try: b.shutdown(socket.SHUT_WR)
                    except Exception: pass
            threading.Thread(target=pump, args=(u, c), daemon=True).start(); pump(c, u)
        except Exception: pass
        finally: c.close()
    def loop():
        while True:
            try: c, _ = ls.accept()
            except OSError: return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1], target

px, tgt = socks_proxy()
def measure(rate, status=b"200 OK", secs=2.0):
    sp, ls = up_server(rate, status); tgt[0] = sp
    try: return C.measure_upload_kbps(px, secs, 2, 4, ["http://upload.test/__up"])
    finally: ls.close()

slow, fast = measure(100), measure(800)   # ~۸۰۰ kbps و ~۶٫۴ Mbps «واقعی» (هر اتصال محدود می‌شه؛ ۲ اتصال = دو برابر)
print("measured upload: slow %s kbps | fast %s kbps" % (slow, fast))
assert slow and fast and fast > 3 * slow, (slow, fast)
assert 1300 < slow < 1900, slow           # ۲ اتصال × ۸۰۰ kbps ≈ ۱۶۰۰
assert measure(800, b"403 Forbidden") is None, "a server that refuses uploads must not get a number"
dead = C.measure_upload_kbps(1, 1.0, 2, 1, ["http://upload.test/__up"]); assert dead is None   # پورتِ بسته: None، بدون کرش

# رتبه‌بندی: حالت آپلود فقط به آپلود نگاه می‌کنه (نه دانلود)
mk = lambda raw, d, u, lat=100: {"raw": raw, "kbps": d, "kbps_up": u, "lat": lat, "flags": set(), "proto": "vless", "security": "tls"}
a, b, c = mk("a", 90000, 2000), mk("b", 5000, 30000), mk("c", 5000, None)
W.CUR[0] = "upload"; assert [x["raw"] for x in sorted([a, b, c], key=W.rk)] == ["b", "a", "c"], "upload rank"
W.CUR[0] = "speed";  assert sorted([a, b, c], key=W.rk)[0]["raw"] == "a", "download rank unchanged"
W.CUR[0] = "upload"; assert W.cost(b) < W.cost(a), "cost must use upload speed in upload mode"
assert W.spd(a, "upload") == 2000 and W.spd(a, "speed") == 90000
# پروفایل: mux و fragment خاموش، و انتخاب‌پذیر
P = cfgforge.PROFILES["upload"]; assert not P["mux"] and not P["fragment"] and "upload" in W.SPEEDLIKE and W.ROUNDS["upload"] >= 2
# check(): در حالت آپلود، live با up=True صدا زده می‌شه و فقط kbps_up پر می‌شه
seen = {}
def fake_live(cc, xray, rounds, timeout, speed=False, secs=3.0, sites=False, call=False, up=False):
    seen["up"], seen["speed"] = up, speed; cc["alive"] = True; cc["kbps_up" if up else "kbps"] = 1234; return cc
real = C.live; C.live = fake_live; W.find_xray = lambda: "x"
W.CUR[0] = "upload"; r = W.check(mk("z", None, None), 1, 3, True, 2.0); assert seen["up"] and r.get("kbps_up") == 1234 and not r.get("kbps")
W.CUR[0] = "speed";  r = W.check(mk("z", None, None), 1, 3, True, 2.0); assert not seen["up"] and r.get("kbps") == 1234
C.live = real
d = W.describe(dict(mk("q", 1, 2), host="h", network="ws", port=443, flags=set())); assert d["kbps_up"] == 2
print("ALL OK")
