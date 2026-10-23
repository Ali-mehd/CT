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


_res_last = ["", 0.0]


def _children_rss_mb():
    """میانگین رم (MB) پردازه‌های xray/sing-box فرزند همین برنامه؛ اگه اندروید اجازه‌ی خوندن نداد None."""
    me, tot, n = os.getpid(), 0.0, 0
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            txt = Path(f"/proc/{d}/status").read_text()
        except OSError:
            continue
        f = dict(l.split(":", 1) for l in txt.splitlines() if ":" in l)
        if f.get("PPid", "").strip() == str(me) and ("xray" in f.get("Name", "") or "sing" in f.get("Name", "")):
            try:
                tot += float(f["VmRSS"].split()[0]) / 1024.0
                n += 1
            except (KeyError, ValueError, IndexError):
                pass
    return tot / n if n else None


def _meminfo():
    """(کل MB، آزاد MB) از /proc/meminfo؛ اگه خونده نشد None. فقط وقتی استفاده می‌شه که جاوا رم رو نداده باشه."""
    try:
        d = {}
        for l in Path("/proc/meminfo").read_text().splitlines():
            k, _, v = l.partition(":")
            d[k] = float(v.split()[0])
        t, a = d.get("MemTotal"), d.get("MemAvailable")
        return (t / 1024.0, a / 1024.0) if t and a is not None else None
    except Exception:
        return None


_rep_last = [""]


def set_env(js):
    """جاوا هر ~۵ ثانیه وضعیت گوشی (JSON) رو می‌ده؛ ضریب مصرف منابع به‌روز می‌شه. هیچ‌وقت خطا برنمی‌گردونه (نباید سرویس رو بیندازه).
    اصل: چیزی حدس زده نمی‌شه؛ اگه سیگنالی نیست در لاگ می‌گیم «در دسترس نیست»."""
    try:
        import cfgres
        g = cfgres.GOV
        try:
            from cfgweb import load_settings
            g.notemp = "full" if load_settings().get("notemp") == "full" else "gentle"
        except Exception:
            pass
        env = json.loads(js)
        if isinstance(env, dict) and (env.get("ram_avail_mb") is None or env.get("ram_total_mb") is None):
            mi = _meminfo()  # راه دوم اندازه‌گیریِ واقعی
            if mi:
                env["ram_total_mb"], env["ram_avail_mb"] = mi
        g.feed(env)
        try:
            m = _children_rss_mb()
            if m:
                g.note_proc_mb(m)
        except Exception:
            pass
        m = _mod[0]
        txt = g.summary()
        if m and txt != _res_last[0] and time.time() - _res_last[1] > 30:  # فقط وقتی تغییر کرد و حداکثر هر ۳۰ ثانیه در لاگ
            _res_last[0], _res_last[1] = txt, time.time()
            m.say(txt if txt else "منابع گوشی عادی شد؛ سرعت اسکن به حالت عادی برگشت.")
        rep = g.report_fa()
        if m and rep != _rep_last[0] and "هنوز" not in rep:
            _rep_last[0] = rep
            m.say("منابع گوشی: " + rep)
    except Exception:
        pass


def quit_all(wipe=False):
    """«خروج کامل»: جستجو و اتصال متوقف، xray/sing-box بسته، یادگیری ذخیره. (خود پروسه را سمت جاوا می‌کشیم.)
    wipe=True: همه‌ی داده‌ی برنامه هم پاک می‌شه (قبل از حذف برنامه)."""
    m = _mod[0]
    if m:
        try:
            m.QUITTING[0] = True
            m.STOP.set()
            t0 = time.time()
            while m.S["stage"] == "running" and time.time() - t0 < 5:
                time.sleep(0.2)
            m.VPN_WANT[0] = False
            m.shutdown()
        except Exception:
            pass
    if wipe:
        import shutil
        for d in (os.environ.get("CFG_DATA"), os.environ.get("TMPDIR")):
            if d:
                shutil.rmtree(d, ignore_errors=True)
    return True
