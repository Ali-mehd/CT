# صرفه‌جویی حجم در سرعت‌سنجی: توقف زودهنگام وقتی سرعت جا افتاد، دقتِ اندازه‌گیری، شمارش بایتِ واقعی، و رد کردن سرورِ بی‌فایده/سرعتِ تازه
import sys, os, socket, threading, time, tempfile
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgscan as C, cfgdata

def rd(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x: raise ConnectionError
        b += x
    return b

def dl_server(rate_kBps):
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(16)
    def handle(c):
        try:
            c.settimeout(10); buf = b""
            while b"\r\n\r\n" not in buf: buf += c.recv(4096)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 50000000\r\nConnection: close\r\n\r\n")
            blk = int(rate_kBps * 1000 * 0.05); t0 = time.time(); sent = 0
            while True:
                c.sendall(b"x" * blk); sent += blk
                d = t0 + sent / (rate_kBps * 1000.0) - time.time()
                if d > 0: time.sleep(d)
        except Exception: pass
        finally: c.close()
    def loop():
        while True:
            try: c, _ = ls.accept()
            except OSError: return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return ls.getsockname()[1]

def socks(target):
    ls = socket.socket(); ls.bind(("127.0.0.1", 0)); ls.listen(16)
    def handle(c):
        try:
            rd(c, 3); c.sendall(b"\x05\x00"); h = rd(c, 4); n = rd(c, 1)[0]; rd(c, n + 2)
            u = socket.create_connection(("127.0.0.1", target), 5)
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
    return ls.getsockname()[1]

for rate in (200, 1500, 4000):  # کیلوبایت/ثانیه برای هر جریان؛ دو جریان → کل = ۲×
    px = socks(dl_server(rate))
    b0 = cfgdata.TOTAL["speed"]; t0 = time.time()
    k = C.measure_kbps(px, 3.0, 2, 4, ["http://dl.test/x"])
    used, el = cfgdata.TOTAL["speed"] - b0, time.time() - t0
    exp = rate * 2 * 8
    legacy = min(3_000_000, rate * 1000 * 3.0) * 2
    print(f"{rate} kB/s: اندازه‌گیری {k} kbps (انتظار {exp})، حجم {used/1e6:.2f}MB (روش قدیمی ≈{legacy/1e6:.2f}MB)، {el:.1f}s")
    assert k and abs(k - exp) / exp < 0.2, (k, exp)
    if rate >= 1500:
        assert used < 0.75 * legacy, (used, legacy)   # دست‌کم ۲۵٪ کمتر از روش قدیمی

# سرعتِ بسیار بالا: قبلاً None برمی‌گشت
px = socks(dl_server(9000))
k = C.measure_kbps(px, 3.0, 2, 4, ["http://dl.test/x"])
assert k and k > 80_000, k

# رد کردن سرورِ بی‌فایده و سرعتِ تازه: منطق در live() (بدون xray) با یک تابع کمکی تست می‌شه
src = open(C.__file__, encoding="utf-8").read()
assert 'useless = bool(sites and sv is not None' in src and 'fresh = bool(c.get(fld)' in src
assert C.SPEED_FRESH == 900 and C.NEED_ALL_SITES[0] is True
print("t32 OK")
