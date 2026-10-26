"""cfgdata - شمارنده‌ی مصرف اینترنتِ خودِ برنامه (بایت‌های واقعی ردوبدل‌شده، به تفکیک دسته).

چرا؟ برنامه برای پیدا کردن سرور سالم هزاران تست می‌زنه و ده‌ها فهرست منبع دانلود می‌کنه؛ روی نت همراه این می‌تونه حجم زیادی باشه
و کاربر باید «عدد واقعی» رو ببینه و سقف بذاره. دسته‌ها:
  scan     تست سرورها (اتصال، دست‌دادن TLS، درخواست‌های سایت‌چک و ...)
  speed    سرعت‌سنجی دانلود/آپلود
  sources  دانلود فهرست منبع‌ها و فهرست سیاه
  probe    پراب سلامت اتصال فعلی (ناظر)
  standby  چک جایگزین‌ها و سایت‌ها در پس‌زمینه
  user     ترافیک خود کاربر از داخل تونل (فقط در «فوق هوشمند» که آمار xray داره)
عدد دقیق بایتِ شبکه نیست (سربار TLS/TCP تخمین ثابت داره)، ولی مرتبه‌ی بزرگی و سهم هر دسته درسته.
فقط کتابخانه‌ی استاندارد؛ به بقیه‌ی برنامه وابسته نیست. هیچ آدرس یا IP ذخیره نمی‌شه، فقط عدد.
"""
import json
import os
import threading
import time
from contextlib import contextmanager

CATS = ("scan", "speed", "sources", "probe", "standby", "user")
_L = threading.Lock()
_TL = threading.local()
TOTAL = {c: 0 for c in CATS}           # از شروع برنامه
DAY = {}                               # {"YYYY-MM-DD": {cat: bytes}}
OVERHEAD_TEST = 6000                   # تخمین سربار هر تست زنده (دست‌دادن TCP/TLS/WS به سرور مقصد)
_dirty = [False]
_path = [None]
_last_save = [0.0]


def today_key():
    return time.strftime("%Y-%m-%d")


def current():
    return getattr(_TL, "cat", None)


@contextmanager
def cat(name):
    """دسته‌ی بایت‌های شمرده‌شده در همین نخ تا پایان بلوک."""
    old = getattr(_TL, "cat", None)
    _TL.cat = name
    try:
        yield
    finally:
        _TL.cat = old


def add(n, c=None):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return
    if n <= 0:
        return
    c = c or getattr(_TL, "cat", None) or "scan"
    if c not in TOTAL:
        c = "scan"
    with _L:
        TOTAL[c] += n
        d = DAY.setdefault(today_key(), {})
        d[c] = d.get(c, 0) + n
        _dirty[0] = True


def today():
    with _L:
        d = dict(DAY.get(today_key(), {}))
    d["total"] = sum(v for k, v in d.items() if k != "user")  # «مصرف برنامه» = همه جز ترافیک خودِ کاربر
    return d


def used_mb():
    return today().get("total", 0) / 1_000_000


def load(path):
    """روزهای قبل رو از دیسک می‌خونه (فایل کوچیک؛ فقط ۱۴ روز آخر)."""
    _path[0] = path
    try:
        d = json.loads(open(path, encoding="utf-8").read())
        if isinstance(d, dict):
            with _L:
                for k, v in d.items():
                    if isinstance(v, dict) and len(k) == 10:
                        DAY[k] = {c: int(x) for c, x in v.items() if c in TOTAL and isinstance(x, (int, float))}
    except Exception:
        pass


def save(force=False):
    p = _path[0]
    if not p or not (_dirty[0] or force):
        return
    if not force and time.time() - _last_save[0] < 30:
        return
    with _L:
        keep = sorted(DAY)[-14:]
        snap = {k: dict(DAY[k]) for k in keep}
        _dirty[0] = False
    _last_save[0] = time.time()
    try:
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(snap, f)
        os.replace(tmp, p)
    except OSError:
        pass


def snapshot():
    """برای گزارش/صفحه: امروز، از شروع اجرا، و ۷ روز اخیر (فقط عدد)."""
    with _L:
        days = {k: dict(v) for k, v in sorted(DAY.items())[-7:]}
        tot = dict(TOTAL)
    return {"today": today(), "since_start": tot, "days": days}
