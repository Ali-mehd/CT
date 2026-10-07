"""cfgandroid - نقطه‌ی ورود پوسته‌ی اندروید. همان cfgweb را در یک نخ بالا می‌آورد و آدرس رابط را برمی‌گرداند.
سرویس جاوا از این ماژول فقط سه چیز می‌خواد: start (بالا آوردن)، status (وضعیت برای ساخت/برچیدن TUN) و set_vpn."""
import json
import os
import threading
import time
from pathlib import Path

_mod = [None]


def start(data, web, geo, native, cache):
    """data: پوشه‌ی داده‌ی خصوصی؛ web: ui.html و blocklist و snapshot؛ geo: geoip/geosite؛ native: nativeLibraryDir."""
    if _mod[0]:
        return url()
    os.environ.update(CFG_ANDROID="1", CFG_DATA=str(data), CFG_NATIVE_DIR=str(native),
                      XRAY_LOCATION_ASSET=str(geo), TMPDIR=str(cache), HOME=str(data))
    import cfgweb  # بعد از تنظیم محیط، چون ثابت‌ها موقع import خوانده می‌شن
    cfgweb.HERE = Path(web)
    _mod[0] = cfgweb
    threading.Thread(target=cfgweb.main, daemon=True, name="cfgweb-main").start()
    t_end = time.time() + 20
    while time.time() < t_end and not (cfgweb.PORT and cfgweb.TOKEN):
        time.sleep(0.05)
    if not (cfgweb.PORT and cfgweb.TOKEN):
        raise RuntimeError("سرور محلی بالا نیومد")
    return url()


def url():
    m = _mod[0]
    return f"http://127.0.0.1:{m.PORT}/?t={m.TOKEN}"


def status():
    """JSON کوچک برای سرویس: مرحله، خواست کاربر برای VPN و پورت SOCKS فعلی."""
    m = _mod[0]
    if not m:
        return json.dumps({"stage": "idle", "want": False, "socks": 0})
    return json.dumps({"stage": m.S["stage"], "want": bool(m.VPN_WANT[0]), "socks": m.SOCKS})


def set_vpn(on):
    if _mod[0]:
        _mod[0].VPN[0] = bool(on)
