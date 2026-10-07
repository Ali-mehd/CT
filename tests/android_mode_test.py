"""تست پایتونِ حالت اندروید روی کامپیوتر (بدون گوشی). اجرا: python3 tests/android_mode_test.py
سرور را با CFG_ANDROID بالا می‌آورد و رفتار امنیتی و API وضعیت را بررسی می‌کند.
این تست VPN، xray و اجرای واقعی روی اندروید را پوشش نمی‌دهد."""
import http.client, json, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "app/src/main/python"))
tmp = Path(tempfile.mkdtemp())
for d in ("data", "cache", "native", "geo"):
    (tmp / d).mkdir()

import cfgandroid
url = cfgandroid.start(tmp / "data", ROOT / "app/src/main/assets/web", tmp / "geo", tmp / "native", tmp / "cache")
import cfgweb
port, tok = cfgweb.PORT, cfgweb.TOKEN


def req(path, hdrs=None, method="GET", body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request(method, path, body=body, headers=dict(hdrs or {}))
    r = c.getresponse(); d = r.read(); c.close()
    return r.status, d


ok = []
def check(name, cond):
    ok.append(cond); print(("PASS " if cond else "FAIL ") + name)

check("url دارای توکن است", url == f"http://127.0.0.1:{port}/?t={tok}")
check("BG روی اندروید True است", cfgweb.BG[0] is True)
check("بدون توکن 403", req("/")[0] == 403)
check("توکن غلط 403", req("/?t=zzz")[0] == 403)
check("توکن درست 200", req(f"/?t={tok}")[0] == 200)
check("Host نامعتبر 403", req(f"/?t={tok}", {"Host": "evil.com"})[0] == 403)
check("Origin بیگانه 403", req(f"/api/state?t={tok}", {"Origin": "http://evil.com"})[0] == 403)
check("Sec-Fetch-Site=cross-site 403", req(f"/api/state?t={tok}", {"Sec-Fetch-Site": "cross-site"})[0] == 403)
check("POST بدون توکن 403", req("/api/stop", method="POST", body=b"{}")[0] == 403)
j = json.loads(req(f"/api/state?t={tok}")[1])
check("state: android=True, win=False", j["android"] is True and j["win"] is False)
check("status() شامل stage/want/socks", set(json.loads(cfgandroid.status())) == {"stage", "want", "socks"})
cfgandroid.set_vpn(True)
check("set_vpn در state دیده می‌شود", json.loads(req(f"/api/state?t={tok}")[1])["vpn"] is True)
check("find_xray بدون فایل خالی", cfgweb.find_xray() == "")
(tmp / "native/libxray.so").write_text("x")
check("find_xray مسیر nativeLibraryDir", cfgweb.find_xray() == str(tmp / "native/libxray.so"))
cfgweb.ensure_ports()
check("پورت تصادفی (نه 10808)", cfgweb.SOCKS != 10808 and cfgweb.HTTP == cfgweb.SOCKS + 1)
req(f"/api/closing?t={tok}", method="POST", body=b"{}"); time.sleep(3.6)
check("بعد از pagehide هنوز زنده است", req(f"/api/state?t={tok}")[0] == 200)
check("صفحه‌ی گزارش 200", req(f"/report?t={tok}")[0] == 200)
sys.exit(0 if all(ok) else 1)
