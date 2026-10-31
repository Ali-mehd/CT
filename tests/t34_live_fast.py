# live(): تست زنده با «xray» ساختگی؛ درخواست‌های IP و صفحه‌ی ساده موازی‌ان، بعد از آخرین دور نمی‌خوابه، و تلاشِ خراب کرش نمی‌کنه
import sys, os, time, tempfile, stat, textwrap, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgscan as C

d = tempfile.mkdtemp()
fake = os.path.join(d, "fakexray.py")
open(fake, "w").write(textwrap.dedent('''
    #!/usr/bin/env python3
    import sys, json, socket, time
    cfg = json.loads(sys.stdin.read())
    port = [i for i in cfg["inbounds"] if "port" in i][0]["port"]
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(8)
    while True:
        try:
            c, _ = s.accept(); c.close()
        except Exception:
            time.sleep(0.1)
'''))
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
wrapper = os.path.join(d, "xray")
open(wrapper, "w").write("#!/bin/sh\nexec python3 %s \"$@\"\n" % fake)
os.chmod(wrapper, 0o755)

link = "vless://11111111-1111-1111-1111-111111111111@example.com:443?type=ws&security=tls&sni=example.com&path=%2F#t"
c = C.parse(link); C.static(c)

cur = {"ip": 0, "plain": 0}
def fake_fetch(port, url, timeout, limit=65536):
    if url == C.LAT_URL:
        return 204, b"", 40
    if url == C.IP_URL:
        time.sleep(0.5); cur["ip"] = time.time(); return 200, b"203.0.113.9", 10
    if url == C.PLAIN_URL:
        time.sleep(0.5); cur["plain"] = time.time(); return 200, b"<html>Example Domain</html>", 10
    raise OSError("unexpected " + url)
C.fetch = fake_fetch

t0 = time.time()
r = C.live(dict(c), wrapper, 1, 3)
dt = time.time() - t0
assert r["alive"] and r["ok"] == 1, r
assert r.get("exit_ip") == "203.0.113.9" and r.get("plain_hash"), "exit ip / plain hash must still be recorded"
assert "tamper" not in r["flags"]
assert dt < 1.45, f"IP و صفحه‌ی ساده باید موازی باشن، نه پشت‌سرهم (طول کشید {dt:.2f}s)"
print(f"alive test with parallel extras: {dt:.2f}s OK")

# tamper هنوز تشخیص داده می‌شه (از نخ موازی)
def fake_fetch2(port, url, timeout, limit=65536):
    if url == C.PLAIN_URL:
        return 200, b"<html><script>evil()</script></html>", 10
    return fake_fetch(port, url, timeout, limit)
C.fetch = fake_fetch2
r = C.live(dict(c, flags=set(c["flags"])), wrapper, 1, 3)
assert "tamper" in r["flags"]; print("tamper detection OK")

# سرور مرده: دور آخر نمی‌خوابه
def dead(port, url, timeout, limit=65536):
    raise TimeoutError("t")
C.fetch = dead
t0 = time.time(); r = C.live(dict(c, flags=set(c["flags"])), wrapper, 1, 3); dt = time.time() - t0
assert not r["alive"] and r["fail"] == "timeout" and dt < 1.0, (r.get("fail"), dt)
print(f"dead server with rounds=1 returns fast ({dt:.2f}s) OK")
t0 = time.time(); r = C.live(dict(c, flags=set(c["flags"])), wrapper, 2, 3); dt2 = time.time() - t0
assert dt2 >= 0.4, "بین دو دور هنوز مکث هست"
print("between-rounds pause kept OK")
