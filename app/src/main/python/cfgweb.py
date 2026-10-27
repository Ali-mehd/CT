#!/usr/bin/env python3
"""cfgweb - هسته‌ی برنامه: سرور محلی + رابط وب (در پنجره‌ی مثل-اپ Edge/Chrome باز می‌شه).
خودش کانفیگ‌ها رو از منابع GitHub پیدا می‌کنه، تست می‌کنه، تنظیمات می‌سازه و وصل می‌شه."""
import atexit, base64, hashlib, math, queue, struct, tempfile, http.server, json, os, random, secrets, shutil, socket, subprocess, sys, threading, time
import ipaddress, re, urllib.parse, urllib.request, webbrowser
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = Path(os.environ.get("CFG_DATA") or ROOT / "data")
sys.path.insert(0, str(HERE))
try:  # [evolve-guard] محافظ تکامل: اگه وصله‌ی تازه برنامه رو بالا نیاورد، خودش برمی‌گرده (این بخش رو وصله نباید حذف کنه)
    import evolve as _ev  # noqa: E402
    _ev.early_guard(ROOT, DATA)
except SystemExit:
    raise
except Exception:
    _ev = None
import cfgscan, cfgforge, report  # noqa: E402
cfgres = None  # تنظیم منابع فقط در نسخه‌ی اندروید هست
import cfgcall  # noqa: E402
import cfgact  # noqa: E402
import cfgdata  # noqa: E402
try:
    import cfgtrace as T  # ردپای بی‌خطر برای گزارش تکامل (خط زمانی، خطاهای بلعیده‌شده، زمان‌سنجی)
except Exception:  # بدون ردپا هم برنامه مثل قبل کار می‌کنه
    class T:
        T0 = time.time()
        evt = err = count = perf = run_begin = run_mark = run_end = incident = staticmethod(lambda *a, **k: None)
        snapshot = staticmethod(lambda *a, **k: {})
try:
    import cfgres  # noqa: E402  (تنظیم خودکار منابع؛ فقط اندروید داده‌اش می‌ده)
except Exception:
    cfgres = None
try:
    import netprobe  # noqa: E402
except Exception:  # بدون سنجش شبکه هم برنامه مثل قبل کار می‌کنه
    netprobe = None
NETP = {"net": None, "shown": None}  # آخرین سنجش شبکه (کوتاه‌مدت؛ با عوض‌شدن اپراتور/مودم دوباره سنجیده می‌شه)

http.server.ThreadingHTTPServer.request_queue_size = 128  # پیش‌فرض ۵ است؛ چند درخواست هم‌زمان از رابط، اتصال‌ها رو رها نکنه

ANDROID = cfgscan.ANDROID  # CFG_ANDROID=1 را فقط پوسته‌ی اندروید تنظیم می‌کند

SOCKS, HTTP, LOCK_PORT = 10808, 10809, 47831
PREV, SRC_DB = DATA / "prev_proxy.json", DATA / "sources.json"
S = dict(stage="idle", step=0, pct=0, msg="آماده‌ست", note="", warn="", log=[], connected=None, blocked=0, beat=time.time())
BG, ASKING, DIRECT, CLOSING, QUITTING = [ANDROID], [False], [""], [0.0], [False]  # اندروید: بسته‌شدن صفحه برنامه را نمی‌بندد
VPN, VPN_WANT, _PORTS = [False], [True], [False]  # VPN: تونل فعاله؛ VPN_WANT: کاربر خواسته
RUN, CUM, STATS_FILE = report.new_stats(), report.new_stats(), DATA / "stats.json"
SETTINGS = DATA / "settings.json"
STOP, XRAY_PROC, WIN, PORT, TOKEN, _lock, PIPE = threading.Event(), None, None, 0, "", None, None


START_LOCK = threading.Lock()


class Cancel(Exception):
    pass


DIAG = {"tested": 0, "ok": 0, "no_reach": 0, "no_traffic": 0, "unsafe": 0, "skip": {}}  # شمارنده‌ی «چرا وصل نشد» (فقط عددهای کلی)


def say(m):
    S["log"] = (S["log"] + [m])[-60:]
    T.evt("log", m)  # همین پیام توی خط زمانیِ گزارش هم (با زمان) می‌ره


# ------------------------------------------------------------ پروکسی ویندوز (با بازیابی خودکار)
def _refresh():
    import ctypes
    w = ctypes.windll.wininet
    w.InternetSetOptionW(0, 39, 0, 0)
    w.InternetSetOptionW(0, 37, 0, 0)


def _key():
    import winreg
    return winreg, winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                                  winreg.KEY_ALL_ACCESS)


def set_proxy(port):
    if os.name != "nt":
        return
    wr, k = _key()
    if not PREV.exists():
        prev = {}
        for n in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                prev[n] = list(wr.QueryValueEx(k, n))
            except OSError:
                prev[n] = None
        PREV.write_text(json.dumps(prev), encoding="utf-8")
    wr.SetValueEx(k, "ProxyEnable", 0, wr.REG_DWORD, 1)
    wr.SetValueEx(k, "ProxyServer", 0, wr.REG_SZ, f"127.0.0.1:{port}")
    wr.SetValueEx(k, "ProxyOverride", 0, wr.REG_SZ, "localhost;127.*;10.*;192.168.*;<local>")
    _refresh()


def restore_proxy():
    if os.name != "nt" or not PREV.exists():
        return
    try:
        wr, k = _key()
        for n, v in json.loads(PREV.read_text(encoding="utf-8")).items():
            if v is None:
                try:
                    wr.DeleteValue(k, n)
                except OSError:
                    pass
            else:
                wr.SetValueEx(k, n, 0, v[1], v[0])
        _refresh()
        PREV.unlink()
    except Exception:
        # فایل پشتیبان (PREV) تا موفقیت پاک نمی‌شه؛ کاربر باید بدونه تنظیم پراکسی ویندوزش برنگشته
        S["warn"] = "بازگردانی تنظیم پراکسی ویندوز انجام نشد؛ اینترنت ممکنه کار نکنه. Settings ← Network ← Proxy رو چک کن و پراکسی رو خاموش کن."


# ------------------------------------------------------------ دیتابیس منابع
def load_db():
    try:
        db = json.loads(SRC_DB.read_text(encoding="utf-8"))
    except Exception:
        db = {}
    if not isinstance(db, dict):  # فایل خراب یا دستی‌ویرایش‌شده نباید برنامه رو از کار بندازه
        db = {}
    db["sources"] = [s for s in (db.get("sources") if isinstance(db.get("sources"), list) else [])
                     if isinstance(s, dict) and isinstance(s.get("url"), str)]
    if "removed" in db:
        db["removed"] = [u for u in (db["removed"] if isinstance(db["removed"], list) else []) if isinstance(u, str)]
    for s in db["sources"]:  # ردیف ناقص/با نوع اشتباه: مقدار پیش‌فرض می‌گیره، بقیه‌ی منابع سالم می‌مونن
        if not isinstance(s.get("on"), bool):
            s["on"] = True
        for k in ("got", "alive"):
            if isinstance(s.get(k), bool) or not isinstance(s.get(k), (int, float)):
                s[k] = 0
    have, removed, changed = {s["url"] for s in db["sources"]}, set(db.get("removed", [])), False
    for u in cfgscan.DEFAULT_SOURCES:  # منبع‌های جدیدِ نسخه‌های تازه خودکار اضافه می‌شن (مگر اینکه خودت حذفشون کرده باشی)
        if u not in have and u not in removed:
            db["sources"].append({"url": u, "on": True, "got": 0, "alive": 0})
            changed = True
    if changed or not SRC_DB.exists():
        save_db(db)
    return db


_ATOMIC_LOCK = threading.Lock()


def _atomic(path, text):
    """نوشتن امن: اگه برنامه وسط نوشتن بسته بشه، فایل قبلی سالم می‌مونه."""
    # نام tmp یکتا برای هر نخ + قفل: دو نوشتن هم‌زمان هم‌دیگر را خراب نکنند
    tmp = Path(f"{path}.{os.getpid()}.{threading.get_ident()}.tmp")
    with _ATOMIC_LOCK:
        try:
            tmp.write_text(text, encoding="utf-8")
            os.replace(tmp, path)
        finally:
            try: tmp.unlink()
            except OSError: pass


def save_db(db):
    DATA.mkdir(parents=True, exist_ok=True)
    _atomic(SRC_DB, json.dumps(db, ensure_ascii=False, indent=1))


def _dpapi(data, enc):
    import ctypes
    from ctypes import wintypes as wt

    class BLOB(ctypes.Structure):
        _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
    buf = ctypes.create_string_buffer(data, len(data))
    inb, out = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if enc else ctypes.windll.crypt32.CryptUnprotectData
    if not fn(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("dpapi")
    res = ctypes.string_at(out.pbData, out.cbData)
    ctypes.windll.kernel32.LocalFree(out.pbData)
    return res


def write_secret(path, text):
    """ذخیره‌ی خصوصی: روی ویندوز با DPAPI رمز می‌شه (فقط همین کاربر ویندوز می‌تونه بخونه)."""
    data = text.encode("utf-8")
    if os.name == "nt":
        try:
            data = b"DPAPI1" + _dpapi(data, True)
        except Exception:
            return False  # رمزگذاری نشد: متن ساده روی دیسک نمی‌نویسیم (فقط ذخیره‌ی این فایل رد می‌شه)
    Path(path).write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return True


def read_secret(path):
    data = Path(path).read_bytes()
    if data.startswith(b"DPAPI1"):
        data = _dpapi(data[6:], False)
    return data.decode("utf-8", "replace")


def read_links(path):
    try:
        return cfgscan.extract_links(read_secret(path))
    except Exception:
        return []


def _in(v, allowed):
    """مقدار از JSON ورودی ممکنه لیست یا دیکشنری باشه؛ `in` روی دیکشنری با مقدار نامعتبر (unhashable) خطا می‌ده."""
    return isinstance(v, str) and v in allowed


def load_settings():
    try:
        d = json.loads(SETTINGS.read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


FA_SPEED = {"gentle": "آرام", "normal": "متعادل", "fast": "سریع", "turbo": "خیلی سریع"}
FA_MODE = {"stable": "هوشمند", "fast": "سریع", "off": "خاموش"}


def apply_live(j, old):
    """تغییر تنظیمات کاربر همین لحظه (بدون ری‌استارت و بدون قطع اتصال) اعمال می‌شه؛ هر تغییر یک پیام فارسی برمی‌گردونه.
    چیزی که وسط اتصال بدون قطع تماس شدنی نیست (پروفایل) صادقانه می‌گه «از اتصال بعدی».
    پیام فقط وقتی داده می‌شه که مقدار نسبت به آخرین مقدار ذخیره‌شده واقعاً عوض شده باشه (باز شدن صفحه پیام الکی نمی‌سازه)."""
    msgs, conn = [], S["stage"] == "connected"

    def changed(k, mem):
        return j.get(k) != old.get(k, mem)

    sp = j.get("speed")
    if _in(sp, SPEEDS):
        ann = changed("speed", SPEED[0])
        SPEED[0] = sp
        if ann:
            gs = cfgres.GOV.summary() if (cfgres is not None and ANDROID) else ""
            msgs.append(f"سرعت اسکن روی «{FA_SPEED.get(sp, sp)}» ذخیره شد." + (" ولی حالت تماس روشنه و سرعت اسکن رو خودش مدیریت می‌کنه؛ بعد از خاموش‌شدنش اعمال می‌شه."
                        if CALL[0] else " و همین الان اعمال شد.") + (f" (ولی {gs})" if gs else ""))
    md = j.get("mode")
    if _in(md, ("stable", "fast", "off")):
        ann = changed("mode", MODE[0])
        MODE[0] = md
        FAILOVER.set() if md != "off" else FAILOVER.clear()
        if ann:
            msgs.append(f"حالت جابه‌جایی «{FA_MODE[md]}» " + ("همین الان اعمال شد." if conn else "برای اتصال بعدی ذخیره شد."))
    if isinstance(j.get("tgonly"), bool):
        ann, was = changed("tgonly", TGONLY[0]), TGONLY[0]
        TGONLY[0] = j["tgonly"]
        if ann and was != TGONLY[0] and conn and POOL["active"]:
            threading.Thread(target=sites_guard, args=(GEN[0], CUR[0], []), daemon=True).start()  # سرور فعلی با نیاز تازه سنجیده می‌شه؛ لازم بود جابه‌جا می‌شه
        if ann:
            msgs.append("حالت اضطراری (فقط تلگرام) روشن شد و همین الان اعمال شد." if TGONLY[0] else
                        "حالت عادی (یوتیوب، اینستاگرام و تلگرام) برگشت؛ سرور فعلی همین الان بررسی می‌شه و اگه لازم باشه جابه‌جا می‌شه.")
    if isinstance(j.get("sysproxy"), bool):
        ann, was = changed("sysproxy", VPN_WANT[0]), VPN_WANT[0]
        VPN_WANT[0] = j["sysproxy"]
        if was != VPN_WANT[0] and conn and not ANDROID:
            try:
                set_proxy(HTTP) if VPN_WANT[0] else restore_proxy()
            except Exception:
                pass
        if ann:
            msgs.append(("پروکسی/VPN سراسری " + ("روشن" if VPN_WANT[0] else "خاموش") + " شد و همین الان اعمال شد.") if conn
                        else "تنظیم پروکسی/VPN برای اتصال بعدی ذخیره شد.")
    d = j.get("direct")
    if isinstance(d, str) and (d == "" or _in(d, cfgforge.COUNTRY_DIRECT)):
        ann, was = changed("direct", DIRECT[0]), DIRECT[0]
        DIRECT[0] = d
        if was != d and conn and POOL["active"]:
            def rebuild():  # مسیرهای مستقیم داخل کانفیگ xray ساخته می‌شن؛ همون سرورها با قانون تازه دوباره بالا میان (حدود ۱–۲ ثانیه)
                try:
                    with SWITCH:
                        if S["stage"] == "connected" and POOL["active"]:
                            start_xray(list(POOL["active"]), CUR[0])
                except Exception:
                    pass
            threading.Thread(target=rebuild, daemon=True).start()
        if ann:
            msgs.append("مسیر مستقیم کشور عوض شد و همین الان اعمال شد (اتصال حدود ۱–۲ ثانیه دوباره بالا میاد)." if (conn and POOL["active"])
                        else "مسیر مستقیم کشور برای اتصال بعدی ذخیره شد.")
    pf = j.get("profile")
    if _in(pf, cfgforge.PROFILES) and changed("profile", CUR[0]):
        msgs.append(f"حالت «{cfgforge.PROFILES[pf]['desc']}» ذخیره شد و از اتصال/جستجوی بعدی اعمال می‌شه "
                    "(وسط اتصال عوضش نمی‌کنم که تماس قطع نشه).")
    for k, fa in (("autosrc", "یافتن خودکار منابع"), ("autores", "تنظیم خودکار منابع گوشی")):
        if k == "autores" and not ANDROID:
            continue  # فقط در نسخه‌ی اندروید معنی داره
        if isinstance(j.get(k), bool) and j[k] != (old.get(k, True) is not False):
            msgs.append(f"{fa} " + ("روشن" if j[k] else "خاموش") + " شد و همین الان اعمال شد.")
    if isinstance(j.get("quick"), bool) and "quick" in old and j["quick"] != old["quick"]:
        msgs.append("نوع جستجو ذخیره شد و از جستجوی بعدی اعمال می‌شه.")
    return msgs


def save_settings(j):
    cur = load_settings()
    applied = apply_live(j, cur)
    if _in(j.get("profile"), cfgforge.PROFILES):
        cur["profile"] = j["profile"]
    if _in(j.get("mode"), ("stable", "fast", "off")):
        cur["mode"] = j["mode"]
    if _in(j.get("speed"), SPEEDS):
        cur["speed"] = j["speed"]
    for k in ("quick", "sysproxy", "tgonly", "autosrc", "call", "autores", "netprobe", "evolve_ok", "hc", "onboarded", "ui2"):
        if isinstance(j.get(k), bool):
            cur[k] = j[k]
    dm = j.get("data_mb")
    if isinstance(dm, int) and not isinstance(dm, bool) and 0 <= dm <= 20000:
        cur["data_mb"] = dm  # سقف مصرف روزانه‌ی خودِ برنامه (مگابایت)؛ ۰ = نامحدود
    elif "data_mb" in j and dm is None:
        cur.pop("data_mb", None)  # «خودکار»
    if "data_mb_user" in j:
        cur["data_mb_user"] = bool(j.get("data_mb_user")) and "data_mb" in cur
    fs = j.get("fs")
    if isinstance(fs, (int, float)) and not isinstance(fs, bool) and 0.8 <= fs <= 1.8:
        cur["fs"] = round(float(fs), 2)  # اندازه‌ی نوشته (ضریب)؛ کاربر در شروع برنامه با دید خودش انتخاب می‌کنه
    if _in(j.get("notemp"), ("gentle", "full")):
        cur["notemp"] = j["notemp"]
        if cfgres is not None:
            cfgres.GOV.notemp = j["notemp"]
    if isinstance(j.get("tgonly"), bool):
        TGONLY[0] = j["tgonly"]
    if _in(j.get("direct", ""), cfgforge.COUNTRY_DIRECT) or j.get("direct") == "":
        cur["direct"] = j.get("direct", "")
    DATA.mkdir(parents=True, exist_ok=True)
    _atomic(SETTINGS, json.dumps(cur))
    return applied








LB_FILE = DATA / "localblock.json"
AVF = [1.0]  # ضریب نرخ اتصال؛ وقتی آنتی‌ویروس/فایروال دستگاه اتصال‌ها رو می‌بنده کم می‌شه (فقط همین اجرا)


def load_localblock():
    """آدرس‌هایی که آنتی‌ویروس/فایروالِ همین دستگاه بسته؛ فقط محلی نگه داشته می‌شه و هیچ‌وقت وارد گزارش نمی‌شه."""
    try:
        d = json.loads(LB_FILE.read_text(encoding="utf-8"))
        now = time.time()
        cfgscan.LOCAL_BLOCK.update({k: v for k, v in d.items() if isinstance(v, (int, float)) and now - v < cfgscan.LOCAL_BLOCK_DAYS * 86400
                                    and cfgscan.is_ip(k)})
    except Exception:
        pass


def save_localblock():
    try:
        now = time.time()
        d = {k: v for k, v in cfgscan.LOCAL_BLOCK.items() if now - v < cfgscan.LOCAL_BLOCK_DAYS * 86400}
        cfgscan.LOCAL_BLOCK.clear()
        cfgscan.LOCAL_BLOCK.update(d)
        write_secret(LB_FILE, json.dumps(d))
    except Exception:
        pass


def _av_note(lbn):
    """آنتی‌ویروس/فایروال چند اتصال رو بسته: خبر به کاربر + کم‌کردن نرخ اتصال (حدس: الگوی «اسکن سریعِ آدرس‌های ناشناس» حساسیتشون رو بالا می‌بره)."""
    frac = lbn[0] / max(1, lbn[1])
    if frac >= 0.02 and AVF[0] > 0.4:
        AVF[0] = 0.4
    say(f"آنتی‌ویروس/فایروالِ این دستگاه {lbn[0]} اتصال از {lbn[1]} تست رو بست؛ این آدرس‌ها رد شدن و خرابیِ سرور حساب نشدن"
        + ("، و نرخ اتصال کم شد تا حساسیتش بالا نره." if AVF[0] < 1 else "."))
    T.evt("local_block", f"{lbn[0]}/{lbn[1]} بسته‌شده، ضریب نرخ {AVF[0]}")
    T.incident("local_block", blocked=lbn[0], tried=lbn[1], pace_factor=AVF[0])


def load_block():
    """فهرست سیاه همراه برنامه + نسخه‌ی به‌روزشده‌ی پس‌زمینه (اگه باشه)."""
    b = cfgscan.Blocklist()
    for p in (HERE / "blocklist.txt", DATA / "blocklist.txt"):
        b.load(p)
    cfgscan.BLOCK = b


def _age_h(path):
    try:
        return (time.time() - path.stat().st_mtime) / 3600
    except OSError:
        return 1e9


def save_net_now():
    """نت همراه یا سقف مصرف پر شده؟ دانلودهای خودکارِ سنگین (فهرست منبع‌ها/فهرست سیاه) تا وقتی نسخه‌ی تازه‌ی کافی داریم تکرار نمی‌شن."""
    return net_is_mobile() or data_saver()


def update_block(force=False):
    """به‌روزرسانی فهرست سیاه؛ با تایم‌اوت، و در صورت خطا همون نسخه‌ی قبلی می‌مونه. force: بدون صبر و بدون چک «کمتر از ۲۴ ساعت»."""
    try:
        if not force:
            time.sleep(30)
        p = DATA / "blocklist.txt"
        if p.exists() and time.time() - p.stat().st_mtime < 86400 and (not force or save_net_now()):
            return  # نت همراه: فهرست سیاهِ کمتر از ۲۴ ساعته دوباره دانلود نمی‌شه (حتی موقع شروع برنامه)
        texts = []
        for u in cfgscan.BLOCK_SOURCES:
            for m in cfgscan.mirror_urls(u):
                try:
                    op = cfgscan.safe_opener()
                    with op.open(urllib.request.Request(m, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "gzip"}), timeout=20) as _r:
                        _raw, _wire = cfgscan._body(_r, 8_000_000)
                    cfgdata.add(_wire + 5000, "sources")
                    texts.append(_raw.decode("utf-8", "replace"))
                    break
                except Exception:
                    continue
        if len(texts) == len(cfgscan.BLOCK_SOURCES):
            data = cfgscan.normalize_blocklist(*texts)
            if data.count("\n") > 5000:  # دانلود ناقص یا خراب جایگزین نشه
                tmp = p.with_suffix(".tmp")
                tmp.write_text(data, encoding="utf-8")
                os.replace(tmp, p)
                load_block()
    except Exception:
        pass


def save_good(cs):
    try:
        p = DATA / "good.txt"
        old = read_links(p)
        new = [c["raw"] for c in cs if c.get("raw")]
        write_secret(p, "\n".join(list(dict.fromkeys(new + old))[:200]) + "\n")
    except Exception:
        pass


# ------------------------------------------------------------ اتصال
def _native(n):
    d = os.environ.get("CFG_NATIVE_DIR")
    p = Path(d) / n if d else None
    return str(p) if p and p.is_file() else ""


def find_singbox():
    if ANDROID:
        return _native("libsingbox.so")
    for n in ("sing-box.exe", "sing-box"):
        if (ROOT / "singbox" / n).is_file():
            return str(ROOT / "singbox" / n)
    return shutil.which("sing-box") or ""


def find_xray():
    if ANDROID:
        return _native("libxray.so")
    for n in ("xray.exe", "xray"):
        if (ROOT / "xray" / n).is_file():
            return str(ROOT / "xray" / n)
    return shutil.which("xray") or ""


POOL = dict(active=[], standby=[], backlog=[], switches=0, real_ip="")
FAILOVER, GEN, POOL_SIZE = threading.Event(), [0], 8


def disconnect(silent=False, keep_proxy=False):
    global XRAY_PROC
    if not keep_proxy:
        restore_proxy()
    if XRAY_PROC:
        XRAY_PROC.terminate()
        try:
            XRAY_PROC.wait(3)
        except subprocess.TimeoutExpired:
            XRAY_PROC.kill()
        XRAY_PROC = None
    APIPORT[0] = 0
    ACT.reset()
    S["act"] = None
    if not silent and S["stage"] == "connected":
        GEN[0] += 1
        S.update(stage="idle", step=0, pct=0, msg="قطع شد", connected=None, note="")
        POOL.update(active=[], standby=[])


def usable(c, only_enc):
    return not (only_enc and (c["security"] == "none" or c["proto"] == "ss"))


def danger(c):
    return any(cfgscan.FLAGS[f][2] == "danger" for f in c["flags"])


def ping_key(c):
    return c.get("lat") or 99999


def check(c, rounds=1, timeout=3, speed=False, secs=3.0, sites=False, call=None, up=None):
    """تست واقعی یه کانفیگ روی یه نمونه‌ی جدا از xray (روی یه کپی تا اصل خراب نشه)."""
    cc = dict(c)
    cc["flags"] = set(c["flags"])
    if sites:  # نتیجه‌ی قدیمی سایت‌ها نباید جای تست تازه بشینه
        cc.pop("sites", None)
    try:
        cfgscan.live(cc, find_xray(), rounds, timeout, speed, secs, sites, CALL[0] if call is None else call,
                    (CUR[0] == "upload") if up is None else up)  # حالت آپلود: به‌جای دانلود، آپلود سنجیده می‌شه
        if cc.get("call"):
            callmem_note(cc, cc["call"])
    except Exception:
        cc["alive"] = False
    cc["verified_at"] = time.time()
    if sites:
        cc["site_t"] = cc["verified_at"]  # زمان آخرین تست یوتیوب/اینستاگرام/تلگرام
    return cc


def check_many(cs, rounds=1, timeout=3, workers=8, speed=False, secs=3.0, sites=False, call=None, up=None):
    if not cs:
        return []
    with ThreadPoolExecutor(max_workers=min(res_workers(workers), len(cs))) as ex:
        return list(ex.map(lambda c: check(c, rounds, timeout, speed, secs, sites, call, up), cs))


MODE = ["stable"]
CUR = ["auto"]
ROUNDS = {"auto": 3, "balanced": 3, "speed": 2, "stable": 5, "secure": 3, "upload": 2}
ACT = cfgact.Sampler()  # فوق هوشمند: تشخیص فعالیتِ فعلی کاربر (فقط وقتی پروفایل auto باشه پر می‌شه)
APIPORT = [0]  # پورت API آمار xray (فقط 127.0.0.1)؛ 0 = غیرفعال


_MOB = [0.0, False]


def net_is_mobile():
    """الان روی نت همراهی؟ (هر ۳ ثانیه یک بار پرسیده می‌شه؛ بدون ترافیک)"""
    if time.time() - _MOB[0] > 3:
        _MOB[0] = time.time()
        try:
            _MOB[1] = netprobe is not None and netprobe.net_kind() == "mob"
        except Exception:
            _MOB[1] = False
    return _MOB[1]


def data_budget_mb():
    """سقف مصرف روزانه‌ی خودِ برنامه (جستجو، سرعت‌سنجی، منابع، پراب). پیش‌فرض: روی نت همراه ۱۵۰ مگابایت، روی مودم/وای‌فای نامحدود. ۰ = نامحدود."""
    st = load_settings()
    v = st.get("data_mb")
    if st.get("data_mb_user") is True and isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 20000:
        return v  # فقط وقتی کاربر خودش از لیست انتخاب کرده (مقدارِ ذخیره‌شده‌ی بدون این نشانه نادیده گرفته می‌شه)
    return 150 if net_is_mobile() else 0


def data_saver():
    """سقف روزانه پر شده؟ اون‌وقت همه‌ی کارهای پس‌زمینه‌ی مصرف‌کننده‌ی اینترنت می‌ایستن (اتصال و نظارت اتصال فعلی می‌مونن)."""
    b = data_budget_mb()
    return bool(b) and cfgdata.used_mb() >= b


def data_view():
    t = cfgdata.today()
    return {"mb": round(t.get("total", 0) / 1e6, 1), "cats": {k: round(v / 1e6, 1) for k, v in t.items() if k != "total"},
            "budget": data_budget_mb(), "saver": data_saver(), "mobile": net_is_mobile()}


def bg_quiet():
    """کارهای پس‌زمینه (تست سایت، سنجش جایگزین‌ها، پر کردن صف) وقتی ساکت می‌شن که تماس باشه (دستی یا تشخیص‌داده‌شده)، کار حساس، یا سقف مصرف نت پر شده باشه."""
    return CALL[0] or (CUR[0] == "auto" and ACT.tracker.act in ("call", "secure"))


def heavy_quiet():
    """کارهای پرمصرف (سرعت‌سنجی پس‌زمینه، دانلود دوباره‌ی منابع) علاوه بر شرایط بالا، با پر شدن سقف مصرف هم می‌ایستن؛
    ولی نگهداری حداقلی (نظارت اتصال، رفرش جایگزین‌ها، پر کردن حداقل ذخیره) هیچ‌وقت به‌خاطر سقف متوقف نمی‌شه تا اتصال خراب نشه."""
    return bg_quiet() or data_saver()

SPEEDLIKE = ("speed", "upload")  # حالت‌هایی که «اندازه‌گیریِ واقعیِ سرعت» روی نامزدها انجام می‌دن (دانلود | آپلود)


def spd(c, m=None):
    """سرعتِ اندازه‌گیری‌شده‌ی مناسب حالت (کیلوبیت/ثانیه): آپلود برای «آپلود»، دانلود برای بقیه؛ ناشناخته = None."""
    return c.get("kbps_up") if (m or CUR[0]) == "upload" else c.get("kbps")
STRICT_BAD = {"no_tls", "weak_cipher", "legacy_aid", "no_sni", "insecure_cert"}


def rk(c):
    """معیار انتخاب بهترین سرور؛ هر حالت یه معیار واقعاً متفاوت داره."""
    m = CUR[0]
    if CALL[0]:  # حالت تماس: فقط کیفیت UDP مهمه (امتیاز MOS بالاتر بهتر)؛ سرورِ بدون اندازه‌گیری بعد از اندازه‌گیری‌شده‌های قابل‌قبول
        return call_key(c) + (eff(c),)
    if m == "speed":
        return (-((c.get("kbps") or 0) // 250), cost(c))
    if m == "upload":  # بیشترین آپلودِ واقعی؛ بین سرورهای هم‌ردیف، همونی که پاسخ‌دهی بهتری داره
        return (-((c.get("kbps_up") or 0) // 250), cost(c))
    if m == "stable":
        return (-(c.get("success") or 0), (c.get("jitter") or 0) + 0.5 * (c.get("lat") or 99999))
    if m == "secure":
        return (0 if c["security"] == "reality" else 1, cost(c))
    return (cost(c), 0)


def cost(c):
    """زمان تخمینی کامل شدن یک صفحه‌ی ~۵۰۰ کیلوبایتی: پاسخ‌دهی + زمان انتقال. پینگ بالا با سرعت خوب می‌تونه از پینگ پایین با سرعت ضعیف بهتر باشه."""
    k = spd(c)  # حالت آپلود: سرعت آپلود؛ بقیه: دانلود
    return (c.get("lat") or 99999) + (4_000_000 / k if k else 2500)


def try_variants(c, xray, timeout):
    """سرور TCP جواب می‌ده ولی اتصال کامل نمی‌شه: fragment و اثرانگشت‌های TLS دیگه رو امتحان می‌کنه."""
    for frag, fp in ((True, ""), (False, "firefox"), (True, "randomized"), (False, "ios")):
        cc = dict(c)
        cc["flags"], cc["frag"], cc["variant"] = set(c["flags"]), frag, True
        if fp:
            cc["fp"] = fp
        try:
            cfgscan.live(cc, xray, 1, timeout)
        except Exception:
            continue
        if cc.get("alive"):
            c.update(cc)
            return True
    return False


def need_ok():
    return 0.99 if CUR[0] in ("stable", "secure") else 0.67


def eff(c):
    """کیفیت مؤثر یک سرور: تأخیر + جریمه‌ی نوسان (نه پینگ لحظه‌ای)."""
    return (c.get("lat") or 99999) + 1.5 * (c.get("jitter") or 0)


def solid(r, need=0.99):
    return bool(r.get("alive")) and not danger(r) and (r.get("success") or 0) >= need


def port_free(p):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ensure_ports():
    """اگه پورت‌های پیش‌فرض اشغالن (مثلاً xray یتیمِ دفعه‌ی قبل یا برنامه‌ی دیگه)، پورت آزاد انتخاب می‌کنه."""
    global SOCKS, HTTP
    if ANDROID and not _PORTS[0]:  # پورت‌های ثابت را برنامه‌های دیگه برای تشخیص VPN اسکن می‌کنن؛ تصادفی
        _PORTS[0] = True
        for _ in range(60):
            b = random.randrange(20000, 60000, 2)
            if port_free(b) and port_free(b + 1):
                SOCKS, HTTP = b, b + 1
                return
    if not (port_free(SOCKS) and port_free(HTTP)):
        for base in range(10810, 10990, 2):
            if port_free(base) and port_free(base + 1):
                SOCKS, HTTP = base, base + 1
                break


def start_singbox(sel):
    """موتور دوم برای hysteria2 / tuic / anytls (سرعت بالا، بر پایه‌ی UDP یا TLS). فایل کانفیگ بعد از بالا اومدن حذف می‌شه."""
    global XRAY_PROC
    old, XRAY_PROC = XRAY_PROC, None
    if old:
        old.terminate()
        try:
            old.wait(2)
        except subprocess.TimeoutExpired:
            old.kill()
    ensure_ports()
    APIPORT[0] = 0  # سینگ‌باکس API آمار xray رو نداره؛ تشخیص فعالیت غیرفعاله
    cfg = cfgscan.build_singbox(sel[0], [
        {"type": "socks", "tag": "s", "listen": "127.0.0.1", "listen_port": SOCKS},
        {"type": "http", "tag": "h", "listen": "127.0.0.1", "listen_port": HTTP}])
    cfg["route"]["rules"] = [{"action": "sniff"}, {"protocol": "bittorrent", "action": "reject"}]
    tmp = tempfile.mkdtemp(prefix="cfg_")
    path = os.path.join(tmp, "c.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)
    sb = cfgscan.SINGBOX
    XRAY_PROC = subprocess.Popen([sb, "run", "-c", path], cwd=os.path.dirname(sb), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        (DATA / "xray.pid").write_text(str(XRAY_PROC.pid), encoding="utf-8")
    except OSError:
        pass
    t_end = time.time() + 9
    while time.time() < t_end and XRAY_PROC.poll() is None:
        try:
            socket.create_connection(("127.0.0.1", SOCKS), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    shutil.rmtree(tmp, ignore_errors=True)
    return sel


def _pick_api_port():
    for _ in range(80):
        p = random.randrange(20000, 60000)
        if p not in (SOCKS, HTTP) and port_free(p):
            return p
    return 0


def start_xray(sel, profile, plain=False):
    """xray رو با لیست سرورها (دوباره) بالا میاره؛ وقتی پورت جواب داد برمی‌گرده."""
    global XRAY_PROC
    if sel and sel[0]["proto"] in cfgscan.SB_PROTOS:
        return start_singbox(sel[:1])
    sel = [c for c in sel if c["proto"] not in cfgscan.SB_PROTOS] or sel
    xray = find_xray()
    want_api = profile == "auto"  # plain فقط fragment/mux رو خاموش می‌کنه؛ آمار و لاگ ربطی بهش نداره (نردبان اتصال اول plain رو امتحان می‌کنه)
    cfg, sel = cfgforge.make_client(sel, profile, None, [], SOCKS, HTTP,
                                    probe_interval="3s" if len(sel) > 1 else "30s", strategy="leastPing", plain=plain,
                                    block_ads=True, direct_country=DIRECT[0], api_port=1 if want_api else 0)
    old, XRAY_PROC = XRAY_PROC, None
    if old:
        old.terminate()
        try:
            old.wait(2)
        except subprocess.TimeoutExpired:
            old.kill()
    ensure_ports()
    cfg["inbounds"][0]["port"], cfg["inbounds"][1]["port"] = SOCKS, HTTP
    api = _pick_api_port() if want_api else 0
    for ib in cfg["inbounds"]:
        if ib.get("tag") == "api-in":
            ib["port"] = api
    if want_api and not api:  # پورت آزاد پیدا نشد؛ بدون تشخیص فعالیت ادامه می‌دیم (اتصال مهم‌تره)
        cfg["inbounds"] = [ib for ib in cfg["inbounds"] if ib.get("tag") != "api-in"]
        cfg["routing"]["rules"] = [r for r in cfg["routing"]["rules"] if r.get("inboundTag") != ["api-in"]]
        for k in ("stats", "api"):
            cfg.pop(k, None)
        cfg["log"] = {"loglevel": "warning"}
        cfg.get("policy", {}).pop("system", None)
    XRAY_PROC = subprocess.Popen([xray, "run", "-c", "stdin:"], cwd=os.path.dirname(xray),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE if api else subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    APIPORT[0] = api
    if api:  # لاگ دسترسی (فقط در حافظه) برای تشخیص فعالیت؛ حتماً باید تخلیه بشه وگرنه xray گیر می‌کنه
        proc = XRAY_PROC
        threading.Thread(target=ACT.reader, args=(proc.stdout, lambda: proc is not XRAY_PROC), daemon=True).start()
    try:  # کانفیگ (با اطلاعات محرمانه‌ی سرور) از طریق stdin می‌ره و هیچ‌وقت روی دیسک نوشته نمی‌شه
        XRAY_PROC.stdin.write(json.dumps(cfg).encode("utf-8"))
        XRAY_PROC.stdin.close()
    except OSError:
        pass
    try:
        (DATA / "xray.pid").write_text(str(XRAY_PROC.pid), encoding="utf-8")
    except OSError:
        pass
    t_end = time.time() + 6
    while time.time() < t_end and XRAY_PROC.poll() is None:
        try:
            socket.create_connection(("127.0.0.1", SOCKS), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    return sel


PROBES = ["http://www.msftconnecttest.com/connecttest.txt", "https://www.gstatic.com/generate_204",
          "https://cp.cloudflare.com/generate_204"]  # همون آدرس‌هایی که خود ویندوز/اندروید/کروم هم می‌زنن


def probe(timeout=1.8, alt=False):
    for u in (PROBES if alt else [random.choice(PROBES)]):
        try:
            st, _, ms = cfgscan.fetch(SOCKS, u, timeout)
            if st in (204, 200):
                return ms
        except Exception:
            pass
    return None


def probe_retry(n=3, timeout=3):
    for _ in range(n):
        if STOP.is_set():
            return None
        ms = probe(timeout, alt=True)
        if ms:
            return ms
        time.sleep(0.4)
    return None


def connect_ladder(cands, profile, pool_size):
    """از کامل‌ترین تنظیمات به ساده‌ترین؛ هر مرحله واقعاً تست می‌شه. (sel, ms) یا None."""
    pool = cands[:pool_size]
    for plain in (True, False):  # اول ساده و سریع؛ ترفندهای کمکی (fragment/mux) فقط اگه لازم شد
        if STOP.is_set():
            return None
        sel = start_xray(pool, profile, plain)
        ms = probe_retry(2, 4)
        if ms:
            return sel, ms, plain
        if pool and pool[0]["proto"] in cfgscan.SB_PROTOS:
            break  # برای موتور دوم حالت ساده/کامل معنی نداره
    for c in cands[:5]:  # سرور به سرور، ساده‌ترین حالت
        if STOP.is_set():
            return None
        if len(pool) == 1 and c is pool[0]:
            continue
        sel = start_xray([c], profile, True)
        ms = probe_retry(2, 4)
        if ms:
            return sel, ms, True
    return None


def direct_ip():
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        ip = op.open(urllib.request.Request(cfgscan.IP_URL, headers={"User-Agent": "Mozilla/5.0"}),
                     timeout=4).read(64).decode().strip()
        ipaddress.ip_address(ip)
        return ip
    except Exception:
        return ""




def describe(c):
    return dict(kbps=c.get("kbps"), kbps_up=c.get("kbps_up"), host=c["host"][:24], proto=c["proto"], network=c["network"], security=c["security"],
                port=c["port"], ping=c.get("tcp_ms") or c.get("lat"), sites=c.get("sites") or None,
                warn=sorted({cfgscan.FLAGS[f][0] for f in c["flags"] if cfgscan.FLAGS[f][2] != "info"}))


def refresh_standby(gen):
    stale = [c for c in POOL["standby"] if time.time() - c.get("verified_at", 0) > 60][:3]
    if not stale:
        return
    res = check_many(stale, 2, 3, 3)
    if GEN[0] != gen:
        return
    new = {id(o): r for o, r in zip(stale, res)}
    keep = []
    for c in POOL["standby"]:
        r = new.get(id(c))
        if r is None:
            keep.append(c)
        elif solid(r, 0.5):
            if "sites" in c:  # این تست سایت‌ها رو نمی‌سنجه؛ نتیجه‌ی قبلی (با زمان خودش) می‌مونه تا standby_sites دوباره بسنجه
                r["sites"], r["site_t"] = c["sites"], c.get("site_t", 0)
            keep.append(r)
    POOL["standby"] = sorted(keep, key=eff)


def set_active(sel, ms=None):
    POOL["active"] = sel
    if S["connected"] and sel:
        S["connected"].update(n=len(sel), warn=describe(sel[0])["warn"],
                              best=f"{sel[0]['proto']} / {sel[0]['network']} / {sel[0]['security']} / پورت {sel[0]['port']}")
        if ms:
            S["connected"]["ms"] = ms


# ---- پایداری جابه‌جایی: جابه‌جایی «اختیاری» (کندی، سایت‌ها، ارتقا) فقط وقتی که اوضاع آرومه؛ قطعیِ واقعی همیشه فوراً رسیدگی می‌شه
MIN_DWELL, FLAP_N, FLAP_WIN, FLAP_HOLD = 150, 3, 600, 900  # حداقل ماندگاری (ثانیه) | ۳ جابه‌جایی در ۱۰ دقیقه = نوسان ⇒ ۱۵ دقیقه ثابت
SW_LOG = deque(maxlen=30)  # (زمان، دلیل)


def _inc_state():
    """عکسِ کوچیک و بی‌خطر از وضعیتِ همین لحظه برای «لحظه‌ی مشکل» (فقط دسته‌ها و عدد؛ بدون آدرس/IP)."""
    try:
        act = (POOL.get("active") or [None])[0]
        return {"stage": S.get("stage"), "link": S.get("link"), "ms": (S.get("connected") or {}).get("ms") if isinstance(S.get("connected"), dict) else None,
                "method": f"{act.get('proto')}/{act.get('network')}/{act.get('security')}" if act else None,
                "port": act.get("port") if act else None, "active_n": len(POOL.get("active") or []), "standby_n": len(POOL.get("standby") or []),
                "sites": POOL.get("sites"), "switches": POOL.get("switches"), "mode": MODE[0], "profile": CUR[0], "call": CALL[0], "net": (NETID[0] or "")[2:8],
                "loadguard_f": round(LOAD.f, 2), "running": RUNNING[0]}
    except Exception as e:
        return {"error": type(e).__name__}
HOLD_UNTIL = [0.0]


def sw_mark(reason):
    now = time.time()
    SW_LOG.append((now, reason))
    T.evt("switch", reason)
    T.incident("switch", why=str(reason)[:80], **_inc_state())
    if sum(1 for t, _ in SW_LOG if now - t < FLAP_WIN) >= FLAP_N:
        HOLD_UNTIL[0] = now + FLAP_HOLD
        say("جابه‌جایی‌های پشت‌سرهم دیده شد؛ برای پایداری تماس‌ها، ۱۵ دقیقه جابه‌جایی اختیاری متوقف شد (قطعیِ واقعی همچنان رسیدگی می‌شه).")
    say(f"جابه‌جایی سرور: {reason}")


def calm_ok():
    """آیا اجازه‌ی جابه‌جایی «اختیاری» (نه قطعی واقعی) هست؟"""
    now = time.time()
    if now < HOLD_UNTIL[0]:
        return False
    return not SW_LOG or now - SW_LOG[-1][0] >= MIN_DWELL


BENCH_STEPS = (20, 60, 180, 420)  # فاصله‌ی بازبینیِ سرورِ کنارگذاشته‌شده بعد از هر شکستِ بازبینی (ثانیه)؛ بعد از چهارمی کنار می‌ره
FLAKY_SEC = 1800  # سروری که قطع شد و برگشت تا ۳۰ دقیقه پشت سرورهای بی‌سابقه‌ی قطعی می‌ره (ولی حذف نمی‌شه)


def flaky(c):
    return c.get("flaky_until", 0) > time.time()


def bench_add(cs):
    """سروری که از دور خارج شد ولی ممکنه هنوز خوب باشه؛ دور ریخته نمی‌شه و زود (۲۰ ثانیه بعد) و بعد با فاصله‌ی بیشتر دوباره سنجیده می‌شه."""
    b = POOL.setdefault("bench", [])
    have = {x["raw"] for x in b}
    now = time.time()
    for c in cs:
        if c["raw"] not in have and not danger(c):
            c.update(bench_fail=0, ok_run=0, cut_t=now, next_t=now + BENCH_STEPS[0])
            b.append(c)
    del b[:-20]


def bench_step():
    """یک دور بازبینی: سرورهایی که وقتشون رسیده (حداکثر ۴ تا) سنجیده می‌شن. فهرست سرورهای سنجیده‌شده رو برمی‌گردونه."""
    bn = POOL.get("bench") or []
    now = time.time()
    cur = {c["raw"] for c in POOL["active"]}
    due = [c for c in bn if c["raw"] not in cur and c.get("next_t", 0) <= now][:4]
    if not due:
        return []
    for c, r in zip(due, check_many(due, 2, 4, 4, sites=True)):
        now = time.time()
        if solid(r) and sites_ok(r) and not danger(r):
            c["ok_run"] = c.get("ok_run", 0) + 1
            if c["ok_run"] < 2:
                c["next_t"] = now + 25  # یک بار سالم کافی نیست؛ ۲۵ ثانیه بعد یک بار دیگه
                continue
            c.update(strikes=0, bench_fail=0, ok_run=0, sites=r["sites"], site_t=now, verified_at=now,
                     success=r.get("success"), ping=r.get("ping"), flaky_until=now + FLAKY_SEC)
            POOL.setdefault("bad", {}).pop((c["host"], c["port"]), None)
            if c["raw"] not in {x["raw"] for x in POOL["standby"]} and len(POOL["standby"]) < 40:
                POOL["standby"].append(c)
            POOL["bench"] = [x for x in POOL["bench"] if x["raw"] != c["raw"]]
        else:
            c["ok_run"] = 0
            c["bench_fail"] = c.get("bench_fail", 0) + 1
            if c["bench_fail"] >= len(BENCH_STEPS):
                POOL["bench"] = [x for x in POOL["bench"] if x["raw"] != c["raw"]]
            else:
                c["next_t"] = now + BENCH_STEPS[c["bench_fail"]]
    return due


def resilient(fn):
    """ناظرهای پس‌زمینه (نوسان‌گیری، چک سایت‌ها، سنجش حالت تماس) با یک خطای غیرمنتظره برای همیشه خاموش نشن؛
    خطا ثبت می‌شه و حلقه بعد از چند ثانیه دوباره شروع می‌شه. با عوض‌شدن اتصال (gen) یا توقف، عادی تموم می‌شه."""
    def wrap(gen, *a, **k):
        while GEN[0] == gen and not STOP.is_set():
            try:
                return fn(gen, *a, **k)
            except Exception as e:
                say(f"ناظر {fn.__name__} خطا داد و دوباره شروع شد: {type(e).__name__}")
                for _ in range(5):
                    if GEN[0] != gen or STOP.is_set():
                        return
                    time.sleep(1)
    wrap.__name__ = fn.__name__
    return wrap


@resilient
def bench_loop(gen):
    """سرورِ کنارگذاشته‌شده رو زود و دوباره می‌سنجه (۲۰، ۶۰، ۱۸۰، ۴۲۰ ثانیه). برای برگشت، دو بازبینیِ سالمِ پشت‌سرهم (با فاصله) لازمه
    تا سروری که فقط یه لحظه سالم دیده شد برنگرده؛ برگشته‌ها با نشانه‌ی «ناپایدار» ۳۰ دقیقه آخر صف می‌شینن. چهار شکست = کنار گذاشته می‌شه."""
    try:
        while GEN[0] == gen and not STOP.is_set():
            for _ in range(5):
                if GEN[0] != gen or STOP.is_set():
                    return
                time.sleep(1)
            if heavy_quiet() or S["stage"] != "connected" or GUARD_LOCK.locked() or not (POOL.get("bench") or []):
                continue
            bench_step()
    except Exception:
        raise


def link_state(hist, fails):
    """وضع لینک از روی نمونه‌های اخیرِ پینگ (None = بی‌جواب): good | jittery | lossy | cut.
    cut: سه نمونه‌ی آخر همگی بی‌جواب (قطعِ کامل، نه نوسان). lossy: نیمی از ۱۲ نمونه‌ی آخر یا بیشتر بی‌جواب. jittery: جواب می‌ده ولی پینگ خیلی می‌پره
    یا ۲۵٪ بی‌جواب. فقط روی ≥۶ نمونه قضاوت می‌کنه؛ کمتر از اون «good»."""
    h = list(hist)[-12:]
    if fails >= 3 and len(h) >= 3 and all(x is None for x in h[-3:]):
        return "cut"
    if len(h) < 6:
        return "good"
    ok = sorted(x for x in h if x)
    loss = 1 - len(ok) / len(h)
    if loss >= 0.5:
        return "lossy"
    if len(ok) >= 6:
        med, p90 = ok[len(ok) // 2], ok[min(len(ok) - 1, int(len(ok) * 0.9))]
        if p90 >= 3 * med and p90 - med >= 300:
            return "jittery"
    return "jittery" if loss >= 0.25 else "good"


def server_cut_confirmed():
    """قطعِ کامل ثابت‌شده: اینترنتِ خودت وصله (کنترل) ولی هیچ‌کدوم از سرورهای فعال دو بار پشت‌سرهم روی TCP جواب ندادن.
    برای پروتکل‌های UDP (hysteria2/tuic) TCP معنی نداره؛ همیشه False (منتظر شمارش عادی می‌مونه)."""
    act = list(POOL.get("active") or [])
    if not act or any(c.get("proto") in ("hysteria2", "tuic") for c in act):
        return False
    targets = []
    for c in act:  # فقط IPِ تأییدشده‌ی همون سرور (همونی که تونل بهش وصله)؛ نام میزبان دوباره resolve نمی‌شه (DNS rebinding)
        try:
            ip = ipaddress.ip_address(c.get("ip") or "")
            if cfgscan.non_public(ip):
                return False
            targets.append((str(ip), int(c["port"])))
        except (ValueError, TypeError, KeyError):
            return False  # IP تأییدشده نداریم؛ به شمارش عادیِ خطاها برمی‌گردیم
    for i in range(2):
        for t in targets:
            try:
                socket.create_connection(t, 2.0).close()
                return False  # سرور هنوز به اتصال جواب می‌ده؛ مشکل از مسیر/تونله، نه قطعِ سرور
            except OSError:
                pass
        if i == 0:
            time.sleep(0.5)
    return net_up()


def failover(gen, profile, sysproxy, mode):
    with SWITCH:
        return _failover(gen, profile, sysproxy, mode)


def standby_ok():
    """جایگزین‌های واقعاً قابل‌استفاده (نه دو بار خراب‌شده و نه توی لیست سیاه ۱۰ دقیقه‌ای). هم جابه‌جایی خودکار و هم تب سرورها از همین استفاده می‌کنن تا با هم نخونن."""
    bad, now = POOL.get("bad", {}), time.time()
    return [c for c in POOL["standby"] if c.get("strikes", 0) < 2 and bad.get((c["host"], c["port"]), 0) < now]


def _failover(gen, profile, sysproxy, mode):
    """فقط وقتی واقعاً قطع/ضعیف شده: سرور جایگزین رو با تست دقیق (چند نمونه) انتخاب می‌کنه."""
    t0 = time.time()
    bad = POOL.setdefault("bad", {})
    if not standby_ok():
        try:
            ms = probe(2.0)
        except Exception:
            ms = None
        if ms:  # جایگزینی نداریم ولی سرور فعلی هنوز (ضعیف) جواب می‌ده: همین‌جا می‌مونیم و هم‌زمان دنبال سرور تازه می‌گردیم
            POOL["refill_fast"] = time.time() + 300
            S["note"] = "سرور جایگزین آماده نیست؛ به همین سرور وصل موندم و در پس‌زمینه دنبال سرور جدید می‌گردم."
            return
    S["note"] = "اتصال قطع یا ضعیف شد؛ در حال انتخاب سرور جایگزین با تست دقیق ..."
    bench_add(POOL["active"])  # ممکنه فقط یه لحظه قطع شده باشه؛ بعداً دوباره سنجیده و اگه سالم بود برمی‌گرده صف
    for c in POOL["active"]:
        c["strikes"] = c.get("strikes", 0) + 1
        bad[(c["host"], c["port"])] = time.time() + 600  # تا ۱۰ دقیقه برنمی‌گرده سراغش
    rest = standby_ok()
    fresh = time.time() - 90
    rest.sort(key=lambda c: (not sites_ok(c), call_key(c) if CALL[0] else (), flaky(c), -((c.get("kbps_up") or 0) // 250) if CUR[0] == "upload" else 0,
                             c.get("verified_at", 0) < fresh, -(c.get("success") or 0), eff(c)))
    tried = set()
    for _ in range(3):  # مسیر سریع: جایگزینی که همین چند ثانیه‌ی پیش کاملاً سالم بوده؛ سلامتش بعد از اتصال دوباره با ترافیک واقعی چک می‌شه
        if GEN[0] != gen or STOP.is_set():
            return
        fastc = sorted([c for c in rest if id(c) not in tried and c.get("verified_at", 0) > time.time() - 45
                        and (c.get("success") or 0) >= 0.99 and not danger(c) and sites_ok(c)
                        and time.time() - c.get("site_t", 0) < SITE_FRESH], key=rk)  # نتیجه‌ی سایت‌های کهنه مسیر سریع رو نمی‌گیره
        if not fastc:
            break
        c = fastc[0]
        tried.add(id(c))
        sel = start_xray([c], profile)
        ms = probe_retry(2, 3)
        if ms:
            POOL["standby"] = [x for x in rest if id(x) not in tried]
            set_active(sel, ms)
            POOL["switches"] += 1
            POOL["sites"] = None
            save_good(sel)
            sw_mark("قطع/ضعف شدید سرور قبلی")
            S.update(msg="وصل شدی ✓", note=f"جابه‌جایی خودکار انجام شد ({time.time() - t0:.1f} ثانیه)")
            threading.Thread(target=sites_guard, args=(gen, profile, []), daemon=True).start()
            return
        bad[(c["host"], c["port"])] = time.time() + 600
    tried.clear()
    for _ in range(3):
        if GEN[0] != gen or STOP.is_set():
            return
        cand = [c for c in rest if id(c) not in tried and bad.get((c["host"], c["port"]), 0) < time.time()][:6]
        if not cand:
            break
        tried.update(id(c) for c in cand)
        good = sorted([r for r in check_many(cand, 2, 3, sites=True) if solid(r)], key=lambda r: (not sites_ok(r), rk(r)))  # فقط سرور کاملاً سالم؛ بین اونا اولویت با سروریه که سایت‌ها رو باز می‌کنه
        if not good or GEN[0] != gen:
            continue
        pool = [g for g in good if sites_ok(g)] or good  # توی حالت کم‌پینگ هم سرورِ بی‌سایت وسط استخر نیاد (مگر چیزی بهتر نباشه)
        sel = start_xray(pool[:POOL_SIZE] if mode == "fast" else pool[:1], profile)
        ms = probe_retry(3, 3)
        if ms:
            POOL["standby"] = [c for c in rest if id(c) not in tried] + [g for g in good if g not in sel]
            set_active(sel, ms)
            POOL["switches"] += 1
            POOL["sites"] = None
            save_good(sel)
            sw_mark("قطع/ضعف شدید سرور قبلی")
            S.update(msg="وصل شدی ✓", note=f"جابه‌جایی خودکار انجام شد ({time.time() - t0:.1f} ثانیه)")
            threading.Thread(target=sites_guard, args=(gen, profile, []), daemon=True).start()
            return
        for g in good[:1]:
            bad[(g["host"], g["port"])] = time.time() + 600
    S["note"] = "سرور آماده‌ای نمونده؛ اسکن دوباره شروع شد ..."
    threading.Thread(target=pipeline, args=(profile, True, sysproxy, mode, True), daemon=True).start()


CALLMEM_FILE = DATA / "callmem.json"
CALLMEM = {"a": {}}  # شبکه (هش) ← روش (proto/network/security) ← [تعداد مؤثر، جمع MOS، زمان آخر]؛ هیچ آدرس سروری ذخیره نمی‌شه
_callmem_lock, _callmem_state = threading.Lock(), {"dirty": False, "t": 0.0}
CALL_HALF = 6 * 3600.0  # نیمه‌عمر تجربه‌ی تماس؛ شرایط شبکه عوض می‌شه


def _callmem_load():
    try:
        j = json.loads(CALLMEM_FILE.read_text(encoding="utf-8"))
        out = {}
        for ctx, ms in list((j.get("a") or {}).items())[:8]:
            if not isinstance(ctx, str) or not isinstance(ms, dict):
                continue
            out[ctx] = {k: [float(v[0]), float(v[1]), float(v[2])] for k, v in list(ms.items())[:40]
                        if isinstance(k, str) and isinstance(v, list) and len(v) == 3 and all(isinstance(x, (int, float)) and math.isfinite(x) and 0 <= x <= 4e9 for x in v)}
        CALLMEM["a"] = out
    except Exception:
        CALLMEM["a"] = {}


def callmem_save(force=False):
    with _callmem_lock:
        if not _callmem_state["dirty"] or (not force and time.time() - _callmem_state["t"] < 30):
            return
        _callmem_state.update(dirty=False, t=time.time())
        try:
            DATA.mkdir(parents=True, exist_ok=True)
            _atomic(CALLMEM_FILE, json.dumps(CALLMEM))
        except OSError:
            pass


def call_method(c):
    return f"{c.get('proto')}/{c.get('network')}/{c.get('security')}"


def callmem_note(c, q):
    """نتیجه‌ی سنجش تماس یک سرور رو برای «همین شبکه» و «همین روش» به یادگیری اضافه می‌کنه (UDP نداشتن = MOS ۱)."""
    ctx = NETID[0]
    if not ctx or not q:
        return
    now = time.time()
    with _callmem_lock:
        ms = CALLMEM["a"].setdefault(ctx, {})
        e = ms.get(call_method(c)) or [0.0, 0.0, now]
        f = 0.5 ** (max(0.0, now - e[2]) / CALL_HALF)
        try:
            mos = float(q.get("mos") or 1.0)
        except (TypeError, ValueError):
            mos = 1.0
        mos = min(4.5, max(1.0, mos)) if math.isfinite(mos) else 1.0  # NaN/بی‌نهایت میانگین رو خراب نکنه
        ms[call_method(c)] = [e[0] * f + 1, e[1] * f + mos, now]
        for k in sorted(ms, key=lambda k: ms[k][2])[:-40]:
            ms.pop(k, None)
        for k in sorted(CALLMEM["a"], key=lambda k: max([v[2] for v in CALLMEM["a"][k].values()] or [0]))[:-8]:
            CALLMEM["a"].pop(k, None)
        _callmem_state["dirty"] = True
    callmem_save()


def callmem_prior(c):
    """میانگین MOS این روش روی این شبکه (اگه حداقل ~۳ نمونه‌ی تازه باشه)؛ وگرنه None."""
    e = (CALLMEM["a"].get(NETID[0]) or {}).get(call_method(c))
    if not e:
        return None
    f = 0.5 ** (max(0.0, time.time() - e[2]) / CALL_HALF)
    return e[1] / e[0] if e[0] * f >= 3 else None


def call_key(c):
    """کلید رتبه‌ی «مناسب برای تماس»: اول سرورهایی که UDP رد می‌کنن و درجه‌ی قابل‌قبول دارن، بعد امتیاز MOS بالاتر؛ سرورِ بدون اندازه‌گیری
    با میانگین یادگرفته‌شده‌ی روشش روی همین شبکه (یا ۲٫۹ اگه چیزی نداریم) بعد از اندازه‌گیری‌شده‌های قابل‌قبول می‌شینه."""
    q = c.get("call")
    if q:
        return (0 if cfgcall.call_ok(q) else 1, -(q.get("mos") or 0))
    pr = callmem_prior(c)
    return (1, -(pr if pr is not None else 2.9))


def set_call(on):
    CALL[0] = cfgforge.CALL[0] = bool(on)
    if not on:
        S["call"] = None
        S["note"] = ""


def call_tips(q):
    """توصیه‌ی کوتاه بر اساس اندازه‌گیری (فقط چیزی که واقعاً اندازه‌گیری شده)."""
    if not q:
        return []
    if not q.get("udp_ok"):
        return ["UDP از این سرور رد نمی‌شه؛ برنامه خودش دنبال سروری با UDP می‌گرده (می‌تونی «بهترین سرور برای تماس» رو هم بزنی). اگه روی هیچ سروری جواب نیومد، احتمالاً STUN روی این شبکه بسته‌ست و نمی‌شه قضاوت کرد."]
    t = []
    if (q.get("loss") or 0) >= 3:
        t.append("افت بسته بالاست: روی Wi-Fi به مودم نزدیک‌تر شو یا جای دیگه امتحان کن؛ همزمان دانلود/آپلود سنگین نداشته باش.")
    if (q.get("jitter") or 0) >= 40:
        t.append("نوسان زیاده: برنامه‌ی دیگه‌ای که اینترنت مصرف می‌کنه (آپدیت، دانلود) رو متوقف کن.")
    if (q.get("p50") or 0) >= 300:
        t.append("تأخیر بالاست: «بهترین سرور برای تماس» رو بزن تا سرور نزدیک‌تر/سریع‌تر انتخاب بشه.")
    return t


def net_view():
    """خلاصه‌ی بی‌خطر آخرین سنجش شبکه برای پنل تشخیص (بدون هیچ آدرس)."""
    r = NETP.get("shown")
    if not r:
        return None
    try:
        return {"ok": bool(r.get("net_ok")), "t": r.get("t"), "ports": {str(k): v for k, v in (r.get("ports") or {}).items()},
                "udp": r.get("udp"), "quic": r.get("quic"), "sni": r.get("sni_filtered"), "frag": r.get("frag"),
                "clock": netprobe.clock_msg_fa(r) if (netprobe and netprobe.clock_bad(r)) else "", "id": (NETID[0] or "")[2:8]}
    except Exception:
        return None


def call_phase():
    """مرحله‌ی حالت تماس برای نمایش: connecting / searching / locked / monitoring / no_udp / idle"""
    if not CALL[0]:
        return ""
    st = S["stage"]
    if st == "running":
        return "connecting"
    if st != "connected":
        return "idle"
    if CALL_SEARCH.locked():
        return "waiting" if CALL_WAIT[0] else "searching"
    q = S.get("call")
    if q and not q.get("udp_ok"):
        return "no_udp"
    return "locked" if (q and cfgcall.call_ok(q, "good")) else "monitoring"


def call_state():
    q = S.get("call") if CALL[0] else None
    managed = dict(mode=eff_mode(MODE[0]), speed=eff_speed(), speed_user=SPEED[0], mode_user=MODE[0]) if CALL[0] else None
    return dict(on=CALL[0], q=q, tips=call_tips(q), tg=f"tg://socks?server=127.0.0.1&port={SOCKS}", android=bool(ANDROID),
                phase=call_phase(), managed=managed)


@resilient
def call_monitor(gen):
    """وقتی حالت تماس روشنه، هر ~۶ ثانیه ۳ نمونه‌ی UDP کوچیک (STUN) از تونل می‌فرسته و کیفیت زنده رو (۴۰ نمونه‌ی اخیر) به‌روز می‌کنه.
    سرور رو خودش عوض نمی‌کنه (وسط تماس تعویض = قطع تماس)؛ فقط اندازه می‌گیره و نشون می‌ده."""
    ring = deque(maxlen=40)
    try:
        while GEN[0] == gen and not STOP.is_set():
            for _ in range(6):
                if GEN[0] != gen or STOP.is_set():
                    return
                time.sleep(1)
            if not CALL[0] or S["stage"] != "connected" or GUARD_LOCK.locked():
                ring.clear()
                continue
            r = cfgcall.measure(SOCKS, count=3, interval=0.3, wait=1.0)
            ring.extend([None] * 3 if r is None else r)
            S["call"] = dict(cfgcall.assess(list(ring)), t=time.time())
    except Exception:
        raise


CALL_KICK = threading.Event()
CALL_RETRY_SECS, CALL_MAX_RETRIES = 180, 6  # فاصله‌ی جستجوی دوباره (ثانیه) و حداکثر دفعات
CALL_WAIT = [False]  # جستجو فعلاً خوابیده و منتظر دور بعدیه (برای نمایش درست مرحله)
CALL_SEARCH = threading.Lock()  # فقط یک جستجوی «سرور مناسب تماس» هم‌زمان


def _call_note(cur, extra=""):
    S["note"] = f"حالت تماس: کیفیت فعلی {cur['grade_fa']} (MOS≈{cur['mos']})" + (f" — {extra}" if extra else "")


def _call_try_switch(gen, profile, cur, best):
    """به سرور `best` می‌پره، دوباره از داخل تونلش تماس رو می‌سنجه؛ بهتر نبود برمی‌گرده. True = جابه‌جا شد."""
    with SWITCH:
        if GEN[0] != gen or not CALL[0] or STOP.is_set():
            return False
        prev = list(POOL["active"])
        sel = start_xray([best], profile)
        ms = probe_retry(3, 3)
        nq = cfgcall.measure_via(SOCKS, 12) if ms else None
        if ms and nq and cfgcall.call_ok(nq, "fair") and nq["mos"] > cur["mos"]:
            POOL["standby"] = [c for c in POOL["standby"] if c["raw"] != sel[0]["raw"]] + prev
            set_active(sel, ms)
            POOL["switches"] += 1
            POOL["sites"] = None
            save_good(sel)
            sw_mark("حالت تماس: سرور بهتر برای تماس")
            S["call"] = dict(nq, t=time.time())
            callmem_note(sel[0], nq)
            S["note"] = f"برای تماس به سرور بهتری رفتی: {nq['grade_fa']} (MOS≈{nq['mos']})"
            return True
        start_xray(prev, profile)  # بهتر نبود؛ برگرد
        return False


def call_prepare(gen, profile, switch=True):
    """حالت تماس روشن شد: خودش دنبال سرور مناسب تماس می‌گرده، کاربر نباید کاری بکنه.
    ۱) اتصال فعلی رو برای UDP می‌سنجه؛ اگه خوب یا عالیه همون می‌مونه.
    ۲) وگرنه جایگزین‌های آماده (که سه سایت رو باز می‌کنن) رو دسته‌دسته می‌سنجه (اول روش‌هایی که روی همین شبکه خوب بوده)
       و به اولین سرور «قابل‌قبول یا بهتر» که واقعاً از داخل تونلش هم تأیید بشه می‌پره.
    ۳) اگه چیزی پیدا نشد بهترین موجود می‌مونه و هر چند دقیقه دوباره می‌گردم (تا وقتی حالت تماس روشنه).
    ۴) اگه روی هیچ سروری UDP جواب نداد، یعنی احتمالاً STUN روی این شبکه بسته‌ست؛ «بد» حساب نمی‌شه و سرور عوض نمی‌شه.
    وسط تماس هیچ‌وقت سرور رو عوض نمی‌کنه (فقط موقع روشن‌کردن یا درخواست کاربر)."""
    if not CALL_SEARCH.acquire(blocking=False):
        return
    try:
        tried, rounds_left, retries = set(), 6, 0
        while GEN[0] == gen and CALL[0] and not STOP.is_set():
            cur = cfgcall.measure_via(SOCKS, 16)
            if cur is None or GEN[0] != gen or not CALL[0]:
                return
            S["call"] = dict(cur, t=time.time())
            if POOL["active"]:
                callmem_note(POOL["active"][0], cur)
            _call_note(cur)
            if cfgcall.call_ok(cur, "good") or not switch:
                return
            any_udp, best_seen = bool(cur.get("udp_ok")), None
            found = False
            while rounds_left > 0 and GEN[0] == gen and CALL[0] and not STOP.is_set():
                pool = [c for c in POOL["standby"] if c["raw"] not in tried and sites_ok(c)]
                cand = sorted(pool, key=lambda c: (call_key(c), eff(c)))[:6]
                if not cand:
                    break
                rounds_left -= 1
                tried.update(c["raw"] for c in cand)
                _call_note(cur, f"دارم سرور مناسب تماس می‌گردم ({len(tried)} سرور سنجیده شد) ...")
                res = check_many(cand, 1, 4, 6, sites=False)  # CALL روشنه؛ هر نتیجه «call» داره
                by = {c["raw"]: c for c in POOL["standby"]}
                for r in res:
                    q = r.get("call")
                    if q and r["raw"] in by:
                        by[r["raw"]]["call"] = q
                        callmem_note(by[r["raw"]], q)
                        any_udp = any_udp or bool(q.get("udp_ok"))
                ok = sorted([r for r in res if solid(r) and cfgcall.call_ok(r.get("call"), "fair")], key=call_key)
                if ok and (not best_seen or call_key(ok[0]) < call_key(best_seen)):
                    best_seen = ok[0]
                if not ok or GEN[0] != gen or STOP.is_set():
                    continue
                top = ok[0]
                if (cfgcall.GRADES.index(top["call"]["grade"]) > cfgcall.GRADES.index(cur["grade"])
                        or top["call"]["mos"] > cur["mos"] + 0.2):
                    if _call_try_switch(gen, profile, cur, top):
                        found = True
                        break
            if found:
                return
            if not any_udp and tried:
                S["note"] = "حالت تماس: روی هیچ سروری UDP جواب نداد؛ احتمالاً STUN روی این شبکه بسته‌ست و این به‌معنی «بد بودن» نیست. سرور عوض نشد."
                return
            cur = S.get("call") or cur
            if cfgcall.call_ok(cur, "fair"):
                _call_note(cur, "جایگزین بهتری پیدا نشد")
                return
            if retries >= CALL_MAX_RETRIES:
                _call_note(cur, "جایگزین بهتری پیدا نشد؛ جستجو متوقف شد (دکمه‌ی «بهترین سرور برای تماس» دوباره می‌گرده)")
                return
            retries += 1
            _call_note(cur, f"بهترین موجود فعلاً همینه؛ تا چند دقیقه دیگه دوباره می‌گردم (بار {retries})")
            CALL_KICK.clear()
            CALL_WAIT[0] = True
            for _ in range(int(CALL_RETRY_SECS)):  # ~۳ دقیقه؛ سرورهای تازه مدام اضافه می‌شن (دکمه‌ی «بهترین سرور برای تماس» بیدارش می‌کنه)
                if GEN[0] != gen or not CALL[0] or STOP.is_set():
                    return
                if CALL_KICK.wait(1):
                    CALL_KICK.clear()
                    retries = 0
                    break
            CALL_WAIT[0] = False
            tried.clear()
            rounds_left = 3
    except Exception:
        pass
    finally:
        CALL_WAIT[0] = False
        CALL_SEARCH.release()


def _call_after_connect(gen, profile):
    for _ in range(12):  # چند ثانیه صبر تا سرورهای آماده (standby) پر بشن
        if GEN[0] != gen or not CALL[0] or STOP.is_set():
            return
        time.sleep(1)
    call_prepare(gen, profile, True)


def upgrade_check(gen, profile, hist):
    with SWITCH:
        return _upgrade_check(gen, profile, hist)


def _upgrade_check(gen, profile, hist):
    """ارتقای نادر و محتاطانه: فقط اگه سرور فعلی مدت‌ها کنده و جایگزین پایدارِ واضحاً بهتری هست. با بازگشت خودکار."""
    ok = sorted(h for h in hist if h)
    if len(ok) < 10 or not calm_ok():
        return
    med = ok[len(ok) // 2]
    if med < 400:
        return  # اختلاف کوچیک ارزش جابه‌جایی نداره
    res = check_many(sorted(POOL["standby"], key=eff)[:4], 4, 4, 4, sites=True)
    good = sorted([r for r in res if solid(r) and sites_ok(r)], key=eff)  # ارتقا هیچ‌وقت به سروری نمی‌ره که یوتیوب/اینستاگرام/تلگرام رو باز نکنه
    if not good or eff(good[0]) > 0.6 * med or GEN[0] != gen or STOP.is_set():
        return
    prev = list(POOL["active"])
    sel = start_xray(good[:1], profile)
    ms = probe_retry(3, 3)
    if ms and ms < 0.8 * med:
        POOL["standby"] = [c for c in POOL["standby"] if c["raw"] != sel[0]["raw"]] + prev
        set_active(sel, ms)
        sw_mark("ارتقا به سرور پایدارتر (فعلی مدت‌ها کند بود)")
        S["note"] = "به یه سرور پایدارتر ارتقا یافت."
    else:
        start_xray(prev, profile)  # بهتر نبود؛ برگرد


SPEEDS = {  # rate: تست اتصال در ثانیه، live: تست زنده‌ی هم‌زمان (هر کدوم یک پردازه‌ی xray)، workers: نخ‌ها
    "gentle": dict(rate=6, live=8, workers=24),
    "normal": dict(rate=15, live=10, workers=40),
    "fast": dict(rate=30, live=14, workers=64),
    "turbo": dict(rate=60, live=20, workers=96),
}
CALL = [bool(load_settings().get("call"))]  # «حالت تماس» (واتساپ/تلگرام): فقط شرایط تماس باکیفیت؛ بقیه‌ی کارها وظیفه‌ش نیست
cfgforge.CALL[0] = CALL[0]
_callmem_load()
TGONLY = [bool(load_settings().get("tgonly"))]  # «حالت اضطراری: فقط تلگرام»؛ پیش‌فرض خاموشه و فقط سروری که هر سه سایت رو باز کنه قبول می‌شه
SITE_CACHE = {}  # نتیجه‌ی تست سه سایت برای هر سرور در همین اجرا
SPEED = [load_settings().get("speed", "normal") if load_settings().get("speed") in ("gentle", "normal", "fast", "turbo") else "normal"]


def eff_speed():
    """سرعت اسکنِ مؤثر. حالت تماس فرمانده‌ست: وسط اتصال پردازش پس‌زمینه باید حداقل باشه (جیتر تماس رو بالا می‌بره)،
    و موقع وصل‌شدن هم از «متعادل» تندتر نمی‌ره. انتخاب کاربر ذخیره می‌مونه و بعد از خاموش‌شدن حالت تماس دوباره اعمال می‌شه."""
    sp = SPEED[0]
    if CALL[0]:
        return "gentle" if S["stage"] == "connected" else {"fast": "normal", "turbo": "normal"}.get(sp, sp)
    if CUR[0] == "auto" and S["stage"] == "connected" and ACT.tracker.act in ("call", "secure", "upload", "download"):
        return "gentle"  # اسکن پس‌زمینه نباید با کار فعلیِ کاربر سر پهنای‌باند و پردازنده دعوا کنه
    return sp


def eff_mode(m):
    """حالت «کم‌پینگ» هر نیم‌ثانیه ترافیک سنجش می‌فرسته و زود سرور عوض می‌کنه؛ وسط تماس مضره. حالت تماس اون رو «هوشمند» می‌کنه.
    «ثابت» انتخاب صریح کاربره و می‌مونه."""
    return "stable" if (CALL[0] and m == "fast") else m


try:
    import resource  # فقط لینوکس/اندروید
except ImportError:
    resource = None


class LoadGuard:
    """ترمز فشار CPU بدون نیاز به سنسور دما: گرمای گوشی از CPUِ پیوسته میاد، پس خودِ CPU اندازه گرفته می‌شه (سنسور دما دیر جواب می‌ده و
    روی بعضی گوشی‌ها اصلاً نیست). هر ~۳ ثانیه (فقط وقتی جستجو در جریانه) دو چیز اندازه‌گیری می‌شه:
      lag:  دیرکردِ یک sleep کوتاه توی همین پردازه. بالا = پردازه خفه شده؛ تست‌ها دیر جواب می‌گیرن و «کندی» به‌حساب «خراب‌بودن سرور» میاد
      duty: سهم CPUِ مصرفی (این پردازه + xrayهای تمام‌شده) از کل هسته‌ها
    ضریب f (بین MIN و ۱) با قانون AIMD عوض می‌شه: کم‌کردنِ سریع، زیادکردنِ آروم؛ و روی تعداد تست هم‌زمان و نرخ شروع اعمال می‌شه.
    سقف‌ها (DUTY) حدسیِ محافظه‌کارانه‌ان و باید با گزارش واقعیِ گوشی تنظیم بشن. فقط اندروید؛ جای دیگه ضریب همیشه ۱ است."""
    MIN, LAG_HI, LAG_LO, EVERY = 0.3, 0.30, 0.10, 3.0
    DUTY = {"gentle": 0.15, "normal": 0.25, "fast": 0.35, "turbo": 0.45}  # سهم مجاز از کل هسته‌ها، به‌ازای سرعت اسکن

    def __init__(self):
        self.f, self.lag, self.duty, self.target = 1.0, None, None, None
        self.min_f, self.n, self.duty_sum, self.log, self._th = 1.0, 0, 0.0, deque(maxlen=20), None

    def update(self, lag, duty, target):
        """یک گام کنترل؛ جدا از اندازه‌گیری تا بشه تست کرد."""
        self.lag = lag if self.lag is None else 0.5 * self.lag + 0.5 * lag
        self.duty = duty if self.duty is None else 0.5 * self.duty + 0.5 * duty
        self.target, f = target, self.f
        if self.lag > self.LAG_HI or self.duty > target * 1.15:
            f = max(self.MIN, f * 0.75)
        elif self.lag < self.LAG_LO and self.duty < target:
            f = min(1.0, f + 0.08)
        if abs(f - self.f) > 1e-9:
            self.log.append([round(time.time() % 100000), round(f, 2), round(self.lag, 3), round(self.duty, 3)])
        self.f = f
        self.min_f = min(self.min_f, f)
        self.n += 1
        self.duty_sum += self.duty

    def apply(self, p, speed):
        self._start()
        if self.f >= 0.999:
            return p
        p = dict(p)
        p["live"] = max(2, int(round(p["live"] * self.f)))
        p["rate"] = max(3, p["rate"] * self.f)
        return p

    def snapshot(self):
        r = lambda x, n: None if x is None else round(x, n)
        return {"on": self._th is not None, "f": round(self.f, 2), "min_f": round(self.min_f, 2), "lag_s": r(self.lag, 3), "duty": r(self.duty, 3),
                "target": self.target, "avg_duty": round(self.duty_sum / self.n, 3) if self.n else None, "steps": self.n, "log": list(self.log)}

    def _start(self):
        if self._th is not None or resource is None or not os.environ.get("CFG_ANDROID") or os.environ.get("CFG_LOADGUARD") == "0":
            return
        if load_settings().get("autores") is False:
            return
        self._th = threading.Thread(target=self._loop, daemon=True)
        self._th.start()

    @staticmethod
    def _cpu():
        a, b = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
        return a.ru_utime + a.ru_stime + b.ru_utime + b.ru_stime

    def _loop(self):
        cores = max(1, os.cpu_count() or 1)
        prev, t_prev = self._cpu(), time.time()
        while True:
            try:
                if not RUNNING[0]:  # جستجو نیست: آروم به حالت عادی برگرد و بیکار بمون
                    self.f = min(1.0, self.f + 0.1)
                    time.sleep(2.0)
                    prev, t_prev = self._cpu(), time.time()
                    continue
                lags = []
                for _ in range(5):
                    t = time.time()
                    time.sleep(0.1)
                    lags.append(max(0.0, time.time() - t - 0.1))
                time.sleep(max(0.0, self.EVERY - 0.5))
                now, cpu = time.time(), self._cpu()
                duty = (cpu - prev) / max(0.1, (now - t_prev) * cores)
                prev, t_prev = cpu, now
                self.update(sum(lags) / len(lags), duty, self.DUTY.get(eff_speed(), 0.25))
            except Exception:
                time.sleep(5.0)


LOAD = LoadGuard()


def speed_params():
    p = dict(SPEEDS[eff_speed()])
    if _ev:  # تعداد تست هم‌زمان خودکار کم و زیاد می‌شه؛ نرخ ارسال (rate) دست‌نخورده می‌مونه
        p = _ev.tune_params(p)
    if os.environ.get("CFG_ANDROID"):  # گوشی: حافظه و باتری محدوده؛ پردازه‌ی xray زیاد باعث بسته‌شدن برنامه توسط اندروید می‌شه
        p["live"], p["workers"] = min(p["live"], 12), min(p["workers"], 64)
        if cfgres is not None and os.environ.get("CFG_RES") != "0" and load_settings().get("autores") is not False:
            p = cfgres.GOV.apply(p)  # بر اساس رم/دما/باتری گوشی؛ بدون داده‌ی جاوا همین p می‌مونه
        p = LOAD.apply(p, eff_speed())  # ترمز CPU (مستقل از سنسورها): اگه پردازه خفه شده یا CPU از سقف رد شده، کمتر و آروم‌تر تست می‌کنه
    return p


def res_workers(n):
    """تعداد نخ‌های کمکی (check_many و...) با ضریب منابع گوشی کم می‌شه؛ روی PC و بدون داده همون n."""
    if cfgres is not None and ANDROID and os.environ.get("CFG_RES") != "0":
        return cfgres.GOV.workers(n)
    return n


class DynLimit:
    """مثل Semaphore ولی سقفش زنده از speed_params() خونده می‌شه؛ با داغ‌شدن گوشی تست‌های تازه کمتر شروع می‌شن و بعد خنک‌شدن آروم زیاد می‌شن
    (تست‌هایی که در جریانن قطع نمی‌شن)."""

    def __init__(self, get):
        self.get, self.n, self.cv = get, 0, threading.Condition()

    def __enter__(self):
        with self.cv:
            while self.n >= max(1, self.get()):
                self.cv.wait(1.0)
            self.n += 1
        return self

    def __exit__(self, *a):
        with self.cv:
            self.n -= 1
            self.cv.notify()


class Pace:
    """سقف نرخ اتصال‌های آزمایشی (در ثانیه)؛ شبکه و اپراتور رو اذیت نکنه و شبیه اسکن پورت نباشه."""

    def __init__(self, rate):  # rate: عدد یا تابعی که نرخ زنده رو برمی‌گردونه
        self.rate, self.t, self.lock = rate, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            r = self.rate() if callable(self.rate) else self.rate
            self.iv = 1.0 / max(0.5, r)
            self.t = max(self.t, now) + self.iv
            w = self.t - self.iv - now
        if w > 0:
            time.sleep(w)


def refill(gen, profile, seen):
    """وقتی وصلی، آروم و پیوسته جایگزین‌های تازه و تست‌شده می‌سازه تا لیست آماده هیچ‌وقت خالی نشه."""
    last_fetch, P = time.time(), cfgforge.PROFILES[profile]
    while GEN[0] == gen and S["stage"] == "connected" and not STOP.is_set():
        time.sleep(10 if POOL.get("refill_fast", 0) > time.time() else 40)  # سرور فعلی ضعیفه و جایگزین نداریم: سریع‌تر دنبال جایگزین بگرد
        if bg_quiet():
            continue  # حالت تماس: ترافیک و پردازش پس‌زمینه ممنوع (جیتر تماس رو بالا می‌بره)
        if GEN[0] != gen or S["stage"] != "connected" or len(POOL["standby"]) >= (6 if net_is_mobile() else 14):
            continue
        if data_saver() and len(POOL["standby"]) >= 3:
            continue  # سقف مصرف پر شده؛ فقط تا حداقلِ ۳ جایگزین ادامه می‌دیم
        batch = [POOL["backlog"].pop(0) for _ in range(min(8, len(POOL["backlog"])))]
        if not batch:
            if time.time() - last_fetch < (1800 if save_net_now() else 600) or data_saver():
                continue  # دانلود دوباره‌ی همه‌ی منابع سنگینه؛ نه هر ۵ دقیقه
            last_fetch = time.time()
            try:  # دانلود دوباره‌ی منابع از داخل خود تونل (حتی اگه GitHub مستقیم بسته باشه)
                urls = [s["url"] for s in load_db()["sources"] if s["on"]]
                links, _ = cfgscan.fetch_sources(urls, per_source=800, log=lambda m: None, stop=STOP.is_set,
                                                 proxy_port=HTTP if XRAY_PROC else None)
                random.shuffle(links)
                for l in links:
                    if l in seen:
                        continue
                    seen.add(l)
                    c = cfgscan.parse(l)
                    if c and cfgscan.ckey(c) not in seen:  # همان سرور با اسم دیگه دوباره تست نشه
                        seen.add(cfgscan.ckey(c))
                        cfgscan.static(c)
                        if not ("unsupported" in c["flags"] or "private_addr" in c["flags"] or danger(c)
                                or not usable(c, P["only_encrypted"])
                                or (P["only_encrypted"] and c["flags"] & STRICT_BAD)):
                            POOL["backlog"].append(c)
            except Exception:
                pass
            continue
        for c in batch:
            cfgscan.reach(c, 3)
        ok = [c for c in batch if c.get("reachable") and not danger(c)]
        have = {x["raw"] for x in POOL["standby"] + POOL["active"]}
        for r in check_many(ok, 2, 5, 3, speed=True):
            if solid(r, need_ok()) and r["raw"] not in have:
                r.setdefault("verified_at", time.time())
                POOL["standby"].append(r)
        POOL["standby"].sort(key=rk)


def supervisor(gen, profile, sysproxy, mode):
    hist, fails, warned, warn_txt = deque(maxlen=45), 0, False, ""
    t_switch = t_eval = t_ref = time.time()
    auto, jit_t0, slow_t0, last_sw = profile == "auto", 0.0, 0.0, (SW_LOG[-1][0] if SW_LOG else 0.0)
    while GEN[0] == gen and S["stage"] == "connected":
        mode = eff_mode(MODE[0])  # کاربر وسط اتصال حالت جابه‌جایی رو عوض کرده باشه همین لحظه اعمال می‌شه؛ حالت تماس «کم‌پینگ» رو هوشمند می‌کنه
        time.sleep(0.5 if (mode == "fast" or fails) else random.uniform(2.0, 4.0))  # سالم: کم‌تعداد و نامنظم؛ مشکوک: سریع‌تر
        if GEN[0] != gen or S["stage"] != "connected":
            return
        dead = XRAY_PROC is None or XRAY_PROC.poll() is not None
        ms = None
        if not dead:
            try:
                with cfgdata.cat("probe"):
                    ms = probe_robust(3.0) if mode == "stable" else probe(1.5)
            except Exception:
                ms = None
        if SW_LOG and SW_LOG[-1][0] != last_sw:  # سرور عوض شده (از هر راهی)؛ نمونه‌های سرور قبلی دیگه معتبر نیستن
            last_sw = SW_LOG[-1][0]
            hist.clear()
            fails, jit_t0, slow_t0 = 0, 0.0, 0.0
        hist.append(ms)
        if ms:
            fails = 0
            if S["connected"]:
                S["connected"]["ms"] = ms
        elif auto and APIPORT[0] and sum(ACT.rates.avg(6)) > 40:
            pass  # فوق هوشمند: ترافیک واقعی داره از تونل رد می‌شه؛ پراب پشت صفِ انتقالِ خودِ کاربر مونده، پس این «قطع» نیست
        else:
            fails += 1
        if mode == "off":
            continue
        okr = [h for h in hist if h]
        lk = link_state(hist, fails)
        if lk != S.get("link"):
            T.evt("link", f"وضع لینک: {S.get('link')} ← {lk} (خطای پشت‌سرهم {fails}، پاسخ {len(okr)}/{len(hist)})")
        S["link"] = lk
        act = ACT.tracker.act if (auto and APIPORT[0]) else ""
        if lk in ("jittery", "lossy") and not S.get("warn"):
            w = "نوسان" if lk == "jittery" else "افت"
            if auto and act in ("upload", "download"):
                S["warn"] = f"{w} در اتصال؛ وسط انتقال حجیم طبیعیه. اگه سرعت کم بمونه خودم سرور سریع‌تر می‌سنجم."
            elif auto and act in ("call", "secure"):
                S["warn"] = f"{w} در اتصال؛ وسط {'تماس' if act == 'call' else 'کار حساس'} سرور رو عوض نمی‌کنم مگر قطع کامل بشه."
            elif auto:
                S["warn"] = f"{w} در اتصال؛ اگه ادامه داشت خودم سرور بهتری می‌گردم."
            else:
                S["warn"] = f"{w} شدید در اتصال فعلی؛ تا قطعِ کامل سرور عوض نمی‌شه."
            warned, warn_txt = True, S["warn"]
        elif lk == "good" and warned and S.get("warn") == warn_txt:
            S["warn"], warned = "", False
        recent = sorted(x for x in list(hist)[-12:] if x)
        med_live = recent[len(recent) // 2] if len(recent) >= 8 else 0
        slow_t0 = (slow_t0 or time.time()) if med_live >= SLOW_MS else 0.0
        if (slow_t0 and time.time() - slow_t0 >= 30 and mode == "stable" and not CALL[0] and POOL["standby"]
                and (not auto or act in ("", "idle", "normal", "interactive")) and time.time() > QUAL["cool"]
                and (not SW_LOG or time.time() - SW_LOG[-1][0] > 60) and calm_ok() and not AUTO_LOCK.locked()):
            QUAL["cool"] = time.time() + 90
            threading.Thread(target=_quality_switch, args=(gen, profile, med_live), daemon=True).start()
        FAILN = 5 if mode == "stable" else 3  # حالت هوشمند: ۵ خطای پشت‌سرهم (≈۱۵–۲۰ ثانیه)، نه ۳ تا؛ خطای لحظه‌ای تماس رو قطع نکنه
        soft = (not CALL[0] and mode == "stable" and len(hist) >= 30 and time.time() - t_switch > 60 and len(okr) / len(hist) < 0.6
                and calm_ok())
        if auto and APIPORT[0]:
            # فوق هوشمند: «نوسان» وسط تماس/کار حساس/انتقال حجیم دلیل جابه‌جایی نیست (انتقال حجیم رو auto_watch با سرعت واقعی می‌سنجه)؛
            # وسط کار عادی هم فقط وقتی نوسان طولانی و پیوسته باشه (گشت‌وگذار حساس‌تره)
            soft = False
            jit_t0 = (jit_t0 or time.time()) if lk in ("jittery", "lossy") else 0.0
            if (act in ("idle", "normal", "interactive") and jit_t0 and len(hist) >= 10 and time.time() - t_switch > 90
                    and time.time() - jit_t0 >= (40 if act == "interactive" else 75) and calm_ok()):
                soft = True
        if (fails >= FAILN or soft) and not dead and not net_up():
            S["note"] = "اینترنتِ خودت قطعه؛ سرور رو عوض نمی‌کنم و منتظر برگشتنش می‌مونم."
            fails = 2  # به‌محض برگشتن اینترنت، دوباره بسنجه
            hist.clear()
            time.sleep(5)
            continue
        cut_now = False
        if not dead and not (fails >= FAILN or soft) and fails >= 3 and POOL["standby"] and lk == "cut":
            cut_now = server_cut_confirmed()  # قطعِ کامل و ثابت‌شده: منتظر ۵ خطا نمی‌مونیم
        if (dead or fails >= FAILN or soft or cut_now) and RUNNING[0] and not POOL["standby"]:
            continue  # هنوز جستجوی اول در حال اجراست و جایگزینی نداریم؛ چند لحظه‌ی دیگه دوباره
        if dead or fails >= FAILN or soft or cut_now:
            why_fo = "هسته مرده" if dead else "قطع کامل تأییدشده" if cut_now else "نوسان/افت طولانی" if soft else f"{fails} خطای پشت‌سرهم"
            T.evt("failover", f"شروع جابه‌جایی خودکار: {why_fo}")
            T.incident("failover", why=why_fo, fails=fails, ok=f"{len(okr)}/{len(hist)}", **_inc_state())
            failover(gen, profile, sysproxy, mode)
            hist.clear()
            fails, t_switch, jit_t0 = 0, time.time(), 0.0
        elif time.time() - t_ref > 60 and not bg_quiet():
            refresh_standby(gen)
            t_ref = time.time()
        elif (not CALL[0] and mode == "stable" and time.time() - t_eval > 600 and time.time() - t_switch > 600
              and (not auto or act in ("", "idle", "normal", "interactive"))):
            upgrade_check(gen, profile, hist)
            t_eval = time.time()


# ── فوق هوشمند: تصمیم بر اساس «الان کاربر چی‌کار می‌کنه» ─────────────────────────────────────────────
CRAWL = {"upload": 900, "download": 2500}  # کیلوبیت بر ثانیه؛ زیر این مقدار، انتقال حجیم «لاک‌پشتی» حساب می‌شه
AUTO = {"diag": {"ticks": 0, "stats_ok": 0, "stats_fail": 0, "flows": 0, "err": ""}, "crawl_t0": 0.0, "cool": 0.0, "tp": {}, "t_cq": 0.0, "call_poor": 0, "call_mos": 0.0, "log": deque(maxlen=30)}
AUTO_LOCK = threading.Lock()  # فقط یک عملیات سنجش/جابه‌جاییِ فوق هوشمند هم‌زمان
HINT = {"idle": "", "normal": "", "interactive": "برای گشت‌وگذار تأخیر کم و ثبات مهمه؛ اگه نوسان ادامه پیدا کنه سرور بهتر می‌گردم.",
        "download": "دانلود حجیم: اگه سرعت خیلی کم بمونه سرور سریع‌تر می‌سنجم.",
        "upload": "آپلود حجیم: اگه سرعت خیلی کم بمونه سرور سریع‌تر برای آپلود می‌سنجم.",
        "call": "تماس: سرور رو وسط تماس عوض نمی‌کنم و فعالیت پس‌زمینه ساکته.",
        "secure": "کار حساس: سرور ثابت می‌مونه (مگر قطع کامل) و فعالیت پس‌زمینه ساکته."}


def auto_log(msg):
    AUTO["log"].append([time.strftime("%H:%M:%S"), msg])
    T.evt("auto", msg)


def _auto_switch(gen, profile, best, why, verify=None):
    """به سرور `best` می‌پره؛ اگه اتصال بالا نیومد یا `verify` رد کرد برمی‌گرده. True = جابه‌جا شد."""
    with SWITCH:
        if GEN[0] != gen or STOP.is_set() or MODE[0] == "off" or S["stage"] != "connected":
            return False
        prev = list(POOL["active"])
        sel = start_xray([best], profile)
        ms = probe_retry(3, 3)
        if ms and (verify is None or verify(ms)):
            POOL["standby"] = [c for c in POOL["standby"] if c["raw"] != sel[0]["raw"]] + prev
            set_active(sel, ms)
            POOL["switches"] += 1
            POOL["sites"] = None
            save_good(sel)
            sw_mark(why)
            return True
        start_xray(prev, profile)  # بهتر نبود یا بالا نیومد؛ برگرد
        return False


def _tp_switch(gen, profile, kind, cur):
    """انتقال حجیم لاک‌پشتی: چند جایگزین رو با «سرعت واقعی آپلود/دانلود» می‌سنجه و فقط به سروری می‌ره که واضحاً سریع‌تره."""
    if not AUTO_LOCK.acquire(blocking=False):
        return
    try:
        up, fld, now = kind == "upload", "kbps_up" if kind == "upload" else "kbps", time.time()
        cands = [c for c in standby_ok() if AUTO["tp"].get(c["raw"], 0) < now]
        cands.sort(key=lambda c: (not sites_ok(c), flaky(c), -((c.get(fld) or 0) // 250), eff(c)))
        cands = cands[:5]
        if not cands:
            S["note"] = "انتقال کنده ولی جایگزین تازه‌ای برای سنجش ندارم؛ در پس‌زمینه دنبال سرور جدید می‌گردم."
            POOL["refill_fast"] = now + 300
            AUTO["cool"] = now + 240
            auto_log(f"انتقال {kind} کند ({round(cur / 8)} KB/s) ولی جایگزینی برای سنجش نبود")
            return
        S["note"] = f"{'آپلود' if up else 'دانلود'} حجیمت کنده ({round(cur / 8)} KB/s)؛ دارم چند سرور رو با سرعت واقعی می‌سنجم ..."
        res = check_many(cands, 1, 4, 3, speed=True, secs=3.0, sites=False, up=up)
        by = {c["raw"]: c for c in POOL["standby"]}
        for r in res:
            AUTO["tp"][r["raw"]] = time.time() + 600  # تا ۱۰ دقیقه دوباره همین‌ها رو نسنج
            if r.get(fld) and r["raw"] in by:
                by[r["raw"]][fld] = r[fld]
        need = max(cur * 2, cur + 1500)
        good = sorted([r for r in res if solid(r) and (r.get(fld) or 0) >= need], key=lambda r: -(r.get(fld) or 0))
        if not good or GEN[0] != gen or STOP.is_set():
            S["note"] = "سرور واضحاً سریع‌تری پیدا نشد؛ با همین ادامه می‌دم و چند دقیقه‌ی دیگه دوباره می‌سنجم."
            POOL["refill_fast"] = time.time() + 300
            AUTO["cool"] = time.time() + 240
            auto_log(f"سنجش {len(res)} سرور برای {kind}: بهتر از {round(cur / 8)} KB/s پیدا نشد")
            return
        best = good[0]
        kb = best[fld]
        if _auto_switch(gen, profile, best, f"انتقال {kind} لاک‌پشتی بود", None):
            AUTO["cool"] = time.time() + 300
            S["note"] = f"سرور سریع‌تر برای {'آپلود' if up else 'دانلود'} پیدا شد (~{round(kb / 8)} KB/s در سنجش)؛ انتقال‌ها دوباره وصل می‌شن."
            auto_log(f"جابه‌جایی برای {kind}: {round(cur / 8)} → ~{round(kb / 8)} KB/s")
        else:
            AUTO["cool"] = time.time() + 240
            S["note"] = "سرور سریع‌تر بالا نیومد؛ برگشتم روی سرور قبلی."
    except Exception as e:
        auto_log(f"خطا در سنجش انتقال: {type(e).__name__}")
    finally:
        AUTO_LOCK.release()


def _post_call_improve(gen, profile):
    """تماس تموم شد و کیفیتش ضعیف بود: حالا (بدون قطع تماس) بهترین سرور برای تماس بعدی رو می‌سنجه و اگه واضحاً بهتر بود می‌ره."""
    if not AUTO_LOCK.acquire(blocking=False):
        return
    try:
        cur_mos = AUTO["call_mos"] or 0.0
        cands = sorted([c for c in standby_ok() if sites_ok(c)], key=lambda c: (call_key(c), eff(c)))[:6]
        if not cands:
            return
        S["note"] = "تماس قبلی کیفیت ضعیفی داشت؛ دارم سرور بهتر برای تماس بعدی می‌سنجم ..."
        res = check_many(cands, 1, 4, 3, sites=False, call=True)
        for r in res:
            if r.get("call"):
                callmem_note(r, r["call"])
        ok = sorted([r for r in res if solid(r) and cfgcall.call_ok(r.get("call"), "fair") and r["call"]["mos"] > cur_mos + 0.3],
                    key=lambda r: -r["call"]["mos"])
        if not ok or GEN[0] != gen:
            S["note"] = "برای تماس بعدی سرور واضحاً بهتری پیدا نشد."
            auto_log("بعد از تماس ضعیف: سرور بهتری پیدا نشد")
            return

        def good_udp(ms):
            q = cfgcall.measure_via(SOCKS, 12)
            return bool(q and cfgcall.call_ok(q, "fair") and q["mos"] > cur_mos)
        if _auto_switch(gen, profile, ok[0], "بعد از تماس ضعیف: سرور بهتر برای تماس", good_udp):
            S["note"] = f"برای تماس بعدی به سرور بهتری رفتم (MOS≈{ok[0]['call']['mos']})."
            auto_log(f"بعد از تماس ضعیف: سرور با MOS≈{ok[0]['call']['mos']}")
    except Exception as e:
        auto_log(f"خطا در بهبود بعد از تماس: {type(e).__name__}")
    finally:
        AUTO_LOCK.release()


QUAL = {"cool": 0.0}
SLOW_MS = 1500  # پینگ واقعیِ میانه‌ی اتصال فعلی که از اون به بعد «کند» حساب می‌شه (سرور وصل می‌شه ولی استفاده‌ش عذابه)


def _quality_switch(gen, profile, cur_med):
    """سرور فعلی «کند ولی وصل»ه (پینگ واقعی مدام بالا). جایگزین‌های آماده رو یکی‌یکی امتحان می‌کنه و به اولین سروری می‌ره که
    با پینگ واقعیِ خودش (نه عدد قدیمیِ تست) واضحاً بهتره؛ اگه بهتر نبود برمی‌گرده."""
    if not AUTO_LOCK.acquire(blocking=False):
        return
    try:
        now = time.time()
        cands = sorted([c for c in standby_ok() if sites_ok(c)], key=lambda c: (flaky(c), eff(c)))[:3]
        if not cands:
            S["note"] = f"سرور فعلی کنده (پینگ واقعی ~{cur_med} ms) ولی جایگزین تأییدشده‌ای ندارم؛ دنبال سرور جدید می‌گردم."
            POOL["refill_fast"] = now + 180
            QUAL["cool"] = now + 240
            auto_log(f"سرور فعلی کند ({cur_med} ms) و جایگزینی نبود")
            return
        S["note"] = f"سرور فعلی کنده (پینگ واقعی ~{cur_med} ms)؛ دارم جایگزین‌ها رو امتحان می‌کنم ..."

        def better(ms):
            xs = [ms] + [probe(3.0) for _ in range(2)]
            xs = sorted(x for x in xs if x)
            return len(xs) >= 2 and xs[len(xs) // 2] < min(0.7 * cur_med, 1800)

        for c in cands:
            if GEN[0] != gen or STOP.is_set():
                return
            if _auto_switch(gen, profile, c, "سرور فعلی کند بود؛ جایگزین سریع‌تر", better):
                QUAL["cool"] = time.time() + 180
                S["note"] = "سرور قبلی کند بود؛ به سروری با پینگ واقعیِ بهتر رفتم."
                auto_log(f"جابه‌جایی برای کندی: ~{cur_med} ms ← سرور بهتر")
                return
        S["note"] = "جایگزین‌های آماده هم بهتر نبودن؛ با همین ادامه می‌دم و دنبال سرور تازه می‌گردم."
        POOL["refill_fast"] = time.time() + 180
        QUAL["cool"] = time.time() + 300
        auto_log(f"{len(cands)} جایگزین امتحان شد و هیچ‌کدوم از {cur_med} ms بهتر نبود")
    except Exception as e:
        T.err("quality_switch", e)
    finally:
        AUTO_LOCK.release()


def _auto_policy(gen, profile, info):
    now, act = time.time(), info["act"]
    if act in CRAWL:
        up15, dn15 = ACT.rates.avg(20)
        cur = up15 if act == "upload" else dn15
        if info["since"] >= 15 and cur < CRAWL[act]:
            AUTO["crawl_t0"] = AUTO["crawl_t0"] or now
        else:
            AUTO["crawl_t0"] = 0.0
        if (AUTO["crawl_t0"] and now - AUTO["crawl_t0"] >= 40 and now > AUTO["cool"] and not AUTO_LOCK.locked()
                and (not SW_LOG or now - SW_LOG[-1][0] > 60) and calm_ok()):
            AUTO["crawl_t0"] = 0.0
            AUTO["cool"] = now + 120
            threading.Thread(target=_tp_switch, args=(gen, profile, act, cur), daemon=True).start()
    else:
        AUTO["crawl_t0"] = 0.0
    if act == "call" and now - AUTO["t_cq"] > 45 and not AUTO_LOCK.locked():
        AUTO["t_cq"] = now
        q = cfgcall.measure_via(SOCKS, 10)
        if q:
            AUTO["call_mos"] = q["mos"]
            if POOL["active"]:
                callmem_note(POOL["active"][0], q)
            AUTO["call_poor"] = AUTO["call_poor"] + 1 if not cfgcall.call_ok(q, "fair") else 0
            S["act"] = dict(S.get("act") or info, q=dict(grade_fa=q["grade_fa"], mos=q["mos"]))
            if AUTO["call_poor"] == 2:
                S["note"] = "کیفیت تماس ضعیفه؛ وسط تماس سرور رو عوض نمی‌کنم، بعد از تموم‌شدنش سرور بهتر می‌گردم."


def auto_watch(gen, profile, sysproxy):
    """هر ۳ ثانیه فعالیت کاربر رو می‌سنجه و سیاست مناسبش رو اعمال می‌کنه (فقط پروفایل «فوق هوشمند»).
    هر خطای غیرمنتظره فقط همون دور رو می‌پرونه و ثبت می‌شه؛ ناظر نمی‌میره."""
    xray, last = find_xray(), "idle"
    AUTO.update(crawl_t0=0.0, call_poor=0, t_cq=0.0)
    AUTO["diag"] = {"ticks": 0, "stats_ok": 0, "stats_fail": 0, "flows": 0, "err": ""}
    D = AUTO["diag"]
    auto_log(f"فوق هوشمند فعال شد (API آمار: {'آماده' if APIPORT[0] else 'نیست'})")
    try:
        while GEN[0] == gen and S["stage"] == "connected" and not STOP.is_set():
            time.sleep(3)
            if GEN[0] != gen or S["stage"] != "connected":
                return
            try:
                proc = XRAY_PROC
                if proc is None or proc.poll() is not None or not APIPORT[0]:
                    S["act"] = None
                    continue
                tot = cfgact.query_stats(xray, APIPORT[0])
                if tot and D.get("_prev") and tot[0] >= D["_prev"][0] and tot[1] >= D["_prev"][1]:
                    cfgdata.add((tot[0] - D["_prev"][0]) + (tot[1] - D["_prev"][1]), "user")  # ترافیک خود کاربر (نه مصرف برنامه)
                D["_prev"] = tot
                D["ticks"] += 1
                D["stats_ok" if tot else "stats_fail"] += 1
                D["flows"] = len(ACT.flows)
                info = ACT.tick(tot)
                act = info["act"]
                S["act"] = dict(info, hint=HINT.get(act, ""), locked=MODE[0] == "off")
                if act != last:
                    auto_log(f"فعالیت: {cfgact.FA[last]} ← {cfgact.FA[act]} ({info.get('reason', '')})")
                    if last == "call" and AUTO["call_poor"] >= 2 and MODE[0] != "off" and time.time() > AUTO["cool"] and calm_ok():
                        AUTO["cool"] = time.time() + 300
                        threading.Thread(target=_post_call_improve, args=(gen, profile), daemon=True).start()
                    if last == "call":
                        AUTO["call_poor"] = 0
                    last = act
                if MODE[0] != "off":
                    _auto_policy(gen, profile, info)
            except Exception as e:
                D["err"] = f"{type(e).__name__}: {str(e)[:80]}"
                T.err("auto_watch", e)
    finally:
        if GEN[0] == gen:
            S["act"] = None

RUNNING = [0]  # تعداد جستجوهای در حال اجرا
SWITCH = threading.RLock()  # فقط یک نفر هم‌زمان سرور فعال رو عوض کنه (جابه‌جایی خودکار، بررسی بعد از جستجو، ارتقا)
PREFETCH = {"links": [], "stats": {}, "t": 0.0, "origin": {}}
PREFETCH_RUNNING = [False]  # فقط اگه به‌روزرسانی اولیه واقعاً شروع شده باشه، جستجو منتظرش می‌مونه
PREFETCH_EVT = threading.Event()  # بعد از تموم‌شدن به‌روزرسانی اولیه‌ی منابع (یا اگه شروع نشد) set می‌شه


FETCHINFO = {"t": 0, "n": 0, "ok": 0, "total": 0}  # آخرین دریافت منابع (برای نمایش «همه‌چیز به‌روزه»)


def record_fetch(stats, n):
    """نتیجه‌ی دریافت هر منبع (تعداد، زمان آخرین موفقیت، علت خطا) رو ذخیره می‌کنه تا توی صفحه دیده بشه."""
    try:
        db = load_db()
        now, ok = int(time.time()), 0
        for x in db["sources"]:
            st = stats.get(x["url"])
            if not st:
                continue
            x["got"], x["err"] = st["got"], st.get("err", "")
            if st["got"]:
                x["last_ok"] = now
                ok += 1
        save_db(db)
        FETCHINFO.update(t=now, n=n, ok=ok, total=len(stats))
    except Exception:
        pass


SITE_FA = {"yt": "یوتیوب", "ig": "اینستاگرام", "tg": "تلگرام"}


FULL = 15  # امتیاز سروری که هر سه سایت رو باز می‌کنه
SITE_FRESH = 900  # نتیجه‌ی تست سایت‌ها تا ۱۵ دقیقه برای جابه‌جایی سریع معتبره
SITE_EVERY, SITE_RETEST = 60, 600  # هر چند ثانیه سرور فعال چک بشه | هر چند ثانیه جایگزین‌ها دوباره سنجیده بشن


def sites_score(c):
    s = c.get("sites") or {}
    return 10 * bool(s.get("yt") and s.get("ig") and s.get("tg")) + 3 * bool(s.get("tg")) + bool(s.get("yt")) + bool(s.get("ig"))


def sites_ok(c):
    """سرور قابل‌قبول؟ حالت عادی: یوتیوب و اینستاگرام و تلگرام هر سه. «حالت اضطراری»: فقط تلگرام."""
    s = c.get("sites") or {}
    if TGONLY[0]:
        return bool(s.get("tg"))
    return bool(s.get("yt") and s.get("ig") and s.get("tg"))


def _closed(r):
    return " و ".join(v for k, v in SITE_FA.items() if not (r or {}).get(k))


def _want():
    return "تلگرام" if TGONLY[0] else "یوتیوب، اینستاگرام و تلگرام"


def site_tiers(cache):
    """چند سرور سالم هر دسته‌اند؟ (برای پیام صادقانه وقتی سرور مناسب پیدا نمی‌شه)"""
    t = dict(full=0, ytig=0, tg=0, tested=0)
    for r in list(cache.values()):
        if not r.get("alive"):
            continue
        s = r.get("sites") or {}
        t["tested"] += 1
        if s.get("yt") and s.get("ig") and s.get("tg"):
            t["full"] += 1
        elif s.get("yt") and s.get("ig"):
            t["ytig"] += 1
        elif s.get("tg"):
            t["tg"] += 1
    return t


# ------------------------------------------------------------ یادگیری محلی
# فقط روی همین دستگاه و بدون اینترنت. به‌جای آدرس سرورها، فقط شمارنده‌ی ویژگی‌ها نگه داشته می‌شه
# (پروتکل، ترنسپورت، پورت، بازه‌ی ساعت، آدرس منبع عمومی) تا برنامه یاد بگیره روی شبکه‌ی تو چی جواب می‌ده.
LEARN_FILE = DATA / "learn.json"
LEARN = {"f": {}, "s": {}, "a": {}, "runs": 0, "disc_t": 0.0, "disc_ok": True}  # f=تجربه‌ی خوب/بد  s=تجربه‌ی امنیتی (خطرناک بودن)  # f[ویژگی] = [تست‌شده، سالم، تست‌سایت، پاس‌سایت]
_learn_lock = threading.Lock()
_learn_state = {"dirty": False, "saved": 0.0}
PORTS_COMMON = (443, 80, 8443, 2053, 2083, 2087, 2096, 8080, 8880)
LEARN_PRIOR = 0.25  # ویژگی‌ای که هنوز تجربه‌ای ازش نداریم، خنثی حساب می‌شه


LEARN_MAX_KEYS = 5000
# ---- یادگیری «به‌تفکیک شبکه» (اپراتور/مودم): ASN خودکار تشخیص داده می‌شه؛ از کاربر چیزی پرسیده نمی‌شه.
# تجربه‌ی هر شبکه جدا نگه داشته می‌شه و کم‌کم (نیمه‌عمر) فراموش می‌شه؛ تجربه‌ی کلی فقط به‌عنوان «پیش‌فرضِ» شبکه‌ی ناشناس/تازه عمل می‌کنه.
LEARN_NETS_MAX, LEARN_NET_KEYS, LEARN_M = 8, 400, 4.0
GLOBAL_W_NEW, GLOBAL_W_KNOWN = 0.35, 0.1  # وزن یادگیری کلی (۰ تا ۱) برای شبکه‌ی تازه | شبکه‌ای که قبلاً چیزی ازش یاد گرفتیم
HALF_DEF, HALF_T, HALF_U = 24 * 3600, 4 * 3600, 12 * 3600  # ساختاری ۲۴ ساعت | ساعت‌روز ۴ ساعت | منبع ۱۲ ساعت
NETID = [""]  # شناسه‌ی شبکه‌ی «همین اجرا»؛ تا سنجش تموم نشده خالیه (تجربه‌ی شبکه‌ی قبلی به این شبکه نسبت داده نشه)
_streak = {}


def net_key():
    return NETID[0]


def _hl(k):
    return HALF_T if k[:1] == "t" else HALF_U if k[:1] == "u" else HALF_DEF


def _decayed(v, k, now):
    f = 0.5 ** (max(0.0, now - v[4]) / _hl(k))
    return [v[0] * f, v[1] * f, v[2] * f, v[3] * f]


def _learn_vec(v):
    """چهار شمارنده‌ی سالم یا None. فایل خراب یا دستی‌ویرایش‌شده (منفی، NaN، بی‌نهایت، موفق بیشتر از آزمایش)
    نباید تقسیم بر صفر یا امتیاز بی‌معنی بسازه."""
    import math
    try:
        x = [float(a) for a in v[:4]]
    except (TypeError, ValueError, OverflowError):
        return None
    if len(x) < 4 or not all(math.isfinite(a) and 0 <= a <= 1e6 for a in x):
        return None
    x[1], x[3] = min(x[1], x[0]), min(x[3], x[2])
    return x


def learn_load():
    try:
        import math
        d = json.loads(LEARN_FILE.read_text(encoding="utf-8"))
        if isinstance(d, dict) and isinstance(d.get("f"), dict):
            f = {}
            for k, v in d["f"].items():
                if len(f) >= LEARN_MAX_KEYS:
                    break
                x = _learn_vec(v) if isinstance(v, list) else None
                if str(k).startswith("u:") and not re.fullmatch(r"u:[0-9a-f]{16}", str(k)):
                    x = None  # کلید خام قدیمیِ URL پاک می‌شه
                if x is not None:
                    f[str(k)[:160]] = x
            LEARN["f"] = f
            sd = {}
            for k, v in (d.get("s") or {}).items():  # بخش امنیتی با همان سخت‌گیری: فقط عددهای متناهی و نامنفی، حداکثر LEARN_MAX_KEYS کلید
                if len(sd) >= LEARN_MAX_KEYS:
                    break
                if (isinstance(v, list) and len(v) >= 2 and not str(k).startswith("t:")
                        and all(isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and 0 <= x <= 1e7 for x in v[:2])
                        and v[1] <= v[0]):
                    sd[str(k)[:160]] = [float(v[0]), float(v[1])]
            LEARN["s"] = sd
            a, now = {}, time.time()
            for nk, nv in (d.get("a") or {}).items() if isinstance(d.get("a"), dict) else []:
                if len(a) >= LEARN_NETS_MAX or not re.fullmatch(r"a:[0-9a-f]{10}", str(nk)) or not isinstance(nv, dict):
                    continue
                ks = {}
                for k, v in (nv.get("k") or {}).items() if isinstance(nv.get("k"), dict) else []:
                    if len(ks) >= LEARN_NET_KEYS or not isinstance(v, list) or len(v) < 5:
                        continue
                    x = _learn_vec(v)
                    try:
                        ts = float(v[4])
                    except (TypeError, ValueError, OverflowError):
                        continue
                    if x is not None and math.isfinite(ts) and 0 < ts <= now + 86400:
                        ks[str(k)[:160]] = x + [ts]
                a[str(nk)] = {"last": min(now, float(nv.get("last", 0)) if isinstance(nv.get("last"), (int, float)) and math.isfinite(nv.get("last")) else 0.0), "k": ks}
            LEARN["a"] = a
            runs, dt = d.get("runs", 0), d.get("disc_t", 0)
            LEARN["runs"] = int(runs) if isinstance(runs, (int, float)) and math.isfinite(runs) and 0 <= runs <= 10 ** 9 else 0
            LEARN["disc_t"] = float(dt) if isinstance(dt, (int, float)) and math.isfinite(dt) and 0 <= dt <= 4e9 else 0.0
            LEARN["disc_ok"] = bool(d.get("disc_ok", True))
    except Exception:
        pass


def learn_save(force=False):
    if not _learn_state["dirty"] or (not force and time.time() - _learn_state["saved"] < 30):
        return
    try:
        with _learn_lock:
            data = json.dumps({"v": 1, "runs": LEARN["runs"], "f": LEARN["f"], "s": LEARN["s"], "a": LEARN["a"], "disc_t": LEARN["disc_t"], "disc_ok": LEARN["disc_ok"]}, ensure_ascii=False)
            _learn_state.update(dirty=False, saved=time.time())
        DATA.mkdir(parents=True, exist_ok=True)
        _atomic(LEARN_FILE, data)
    except Exception:
        pass


def learn_reset():
    with _learn_lock:
        LEARN["f"], LEARN["s"], LEARN["a"], LEARN["runs"] = {}, {}, {}, 0
        _learn_state["dirty"] = False
        BAD["h"].clear()
        _bad_state["dirty"] = False
        CALLMEM["a"] = {}
        _callmem_state["dirty"] = False
    for f in (LEARN_FILE, BAD_FILE, CALLMEM_FILE):
        try:
            f.unlink()
        except OSError:
            pass


def _uk(url):
    """کلید منبع روی دیسک: هش. لینک اشتراک (ساب) معمولاً توکن شخصی داره و نباید خام توی learn.json بمونه."""
    return "u:" + hashlib.sha256(str(url).encode("utf-8", "replace")).hexdigest()[:16]


def learn_keys(c):
    pt = c.get("port")
    pr, nw, sc = (str(c.get(k) or "")[:20] for k in ("proto", "network", "security"))  # طول کلید محدود
    ks = ["p:" + pr, "n:" + nw, "s:" + sc,
          "o:" + (str(pt) if pt in PORTS_COMMON else "other"),
          f"t:{time.localtime().tm_hour // 4}:{pr}:{nw}"]  # ساعت روز هم اثر داره
    if c.get("srcurl"):
        ks.append(_uk(c["srcurl"]))
    return ks


def learn_record(c, kind):
    """kind='live': آیا این سرور اصلاً کار کرد؟  kind='site': (فقط برای سالم‌ها) آیا همه‌ی سایت‌های لازم رو باز کرد؟"""
    try:
        now, nk = time.time(), net_key()
        pred = learn_score(c, True) if (nk and kind == "live") else 0.0  # پیش‌بینی قبل از ثبت (برای تشخیص تغییر شرایط)
        with _learn_lock:
            if nk:
                _record_local(c, kind, nk, now, pred)
            for k in learn_keys(c):
                if k not in LEARN["f"] and len(LEARN["f"]) >= LEARN_MAX_KEYS:  # حافظه و فایل بی‌حد رشد نکنن
                    continue
                v = LEARN["f"].setdefault(k, [0.0, 0.0, 0.0, 0.0])
                if kind == "live":
                    v[0] += 1
                    v[1] += 1 if c.get("alive") else 0
                else:
                    v[2] += 1
                    v[3] += 1 if sites_ok(c) else 0
                if v[0] > 400 or v[2] > 200:  # تجربه‌ی قدیمی کم‌کم کم‌اثر می‌شه؛ شبکه عوض می‌شه
                    v[:] = [x / 2 for x in v]
            _learn_state["dirty"] = True
        learn_save()
    except Exception:
        pass


def _record_local(c, kind, nk, now, pred):
    a = LEARN["a"]
    if nk not in a:
        if len(a) >= LEARN_NETS_MAX:  # قدیمی‌ترین شبکه کنار می‌ره
            a.pop(min(a, key=lambda x: a[x].get("last", 0)), None)
        a[nk] = {"last": now, "k": {}}
    n = a[nk]
    n["last"] = now
    ks = n["k"]
    if kind == "live":  # تغییر شرایط: چند سرورِ «امیدوارکننده» پشت‌سرهم شکست = تجربه‌ی قبلی این شبکه دیگه معتبر نیست؛ سریع‌تر فراموش کن
        if pred >= 0.5:
            _streak[nk] = 0 if c.get("alive") else _streak.get(nk, 0) + 1
            if _streak[nk] >= 4:
                _streak[nk] = 0
                for kk, vv in ks.items():
                    vv[:4] = [x * 0.25 for x in vv[:4]]
    for k in learn_keys(c):
        v = ks.get(k)
        if v is None:
            if len(ks) >= LEARN_NET_KEYS:
                ks.pop(min(ks, key=lambda x: ks[x][4]), None)
            v = ks[k] = [0.0, 0.0, 0.0, 0.0, now]
        v[:4] = _decayed(v, k, now)
        v[4] = now
        if kind == "live":
            v[0] += 1
            v[1] += 1 if c.get("alive") else 0
        else:
            v[2] += 1
            v[3] += 1 if sites_ok(c) else 0


def learn_score(c, alive_only=False):
    """احتمال تخمینی اینکه این سرور هم کار کنه هم سایت‌های لازم رو باز کنه (۰ تا ۱)."""
    ar, sr, rk = [], [], []
    f, sec = LEARN["f"], LEARN["s"]
    nk, now = net_key(), time.time()
    loc = LEARN["a"].get(nk, {}).get("k", {}) if nk else {}
    gw = GLOBAL_W_NEW if not loc else GLOBAL_W_KNOWN  # یادگیری کلی از همه‌ی شبکه‌ها قاطیه؛ برای شبکه‌ی تازه کم‌اثر، برای شبکه‌ی شناخته‌شده تقریباً بی‌اثر
    for k in learn_keys(c):
        v = f.get(k)
        ga = (v[1] + 1) / (v[0] + 4) if v else LEARN_PRIOR  # کلی = پیش‌فرض شبکه‌ی تازه
        gs = (v[3] + 1) / (v[2] + 4) if v else LEARN_PRIOR
        if k[:1] != "u":  # کیفیت «منبع» به شبکه وابسته نیست و همون‌طور می‌مونه؛ بقیه (پروتکل، پورت، ...) به شبکه وابسته‌ان
            ga, gs = LEARN_PRIOR + gw * (ga - LEARN_PRIOR), LEARN_PRIOR + gw * (gs - LEARN_PRIOR)
        lv = loc.get(k)
        if lv:  # تجربه‌ی همین شبکه (با نیمه‌عمر) بر پیش‌فرض کلی غالب می‌شه؛ با داده‌ی کم به کلی نزدیکه (shrinkage)
            d = _decayed(lv, k, now)
            ga, gs = (d[1] + LEARN_M * ga) / (d[0] + LEARN_M), (d[3] + LEARN_M * gs) / (d[2] + LEARN_M)
        ar.append(ga)
        sr.append(gs)
        d = sec.get(k)  # ویژگی‌های عمومی (مثلاً tls یا پورت ۴۴۳) بین همه‌ی سرورها مشترکن؛ پس میانگین می‌گیریم تا ویژگی‌های اختصاصی تعیین‌کننده باشن
        rk.append(d[1] / (d[0] + 10) if d and d[0] >= 8 else 0.0)
    if alive_only:
        return sum(ar) / len(ar)
    risk = sum(rk) / len(rk)
    return (sum(ar) / len(ar)) * (sum(sr) / len(sr)) * (1 - min(0.9, risk * 2))  # الگوی بارها خطرناک‌شده امتیازش پایین میاد


def _mkey(c):
    """کلید «روش» کانفیگ، هم‌شکل با جدول روش‌های گزارش (پروتکل/انتقال/امنیت)."""
    return f"{c.get('proto')}/{c.get('network')}/{c.get('security')}"


def _src_prior(url):
    """(احتمال زنده‌بودن، احتمال باز کردن سایت‌ها، تعداد تست) این منبع؛ از تجربه‌ی همین شبکه روی تجربه‌ی کلی."""
    k = _uk(url) if url else ""
    v = LEARN["f"].get(k) if k else None
    ga = (v[1] + 1) / (v[0] + 4) if v else LEARN_PRIOR
    gs = (v[3] + 1) / (v[2] + 4) if v else LEARN_PRIOR
    n = v[0] if v else 0.0
    nk = net_key()
    lv = (LEARN["a"].get(nk, {}).get("k", {}) if nk else {}).get(k) if k else None
    if lv:
        d = _decayed(lv, k, time.time())
        ga, gs, n = (d[1] + LEARN_M * ga) / (d[0] + LEARN_M), (d[3] + LEARN_M * gs) / (d[2] + LEARN_M), d[0]
    return ga, gs, n


def src_score(url):
    """چقدر این منبع «کانفیگ خوب» می‌ده (۰ تا ~۱): احتمال زنده بودن × احتمال باز کردن سایت‌ها، از تجربه‌ی همین شبکه روی تجربه‌ی کلی.
    منبعی که کم تست شده یه امتیاز کنجکاوی کوچیک می‌گیره تا منبع تازه هم شانس بگیره، ولی منبع ثابت‌شده‌ی خوب همیشه جلوتره."""
    ga, gs, n = _src_prior(url)
    return ga * gs + 0.12 / (1.0 + n) ** 0.5


LINKS_CAP = 9000  # سقف کانفیگ‌هایی که یک جستجو نگه می‌داره (حافظه و کش)


def balance_links(links, origin, cap=LINKS_CAP):
    """وقتی کانفیگ‌ها از سقف بیشترن، به‌جای بریدن تصادفیِ کل لیست (که منبع کوچیکِ خوب رو هم تا ~۷۰٪ می‌ریخت دور)، هر منبع یه سهم کف
    داره و بقیه‌ی ظرفیت به نسبت امتیاز منبع (src_score) پخش می‌شه. منبعی که از سهمش کوچیک‌تره کامل می‌مونه. ترتیب خروجی تصادفیه."""
    links = list(links)
    if len(links) <= cap:
        random.shuffle(links)
        return links
    groups = {}
    for l in links:
        groups.setdefault(origin.get(l, ""), []).append(l)
    for g in groups.values():
        random.shuffle(g)
    floor = cap // (4 * len(groups))
    take = {u: min(len(g), floor) for u, g in groups.items()}
    left = cap - sum(take.values())
    w = {u: max(0.02, src_score(u)) for u in groups}
    active = {u for u, g in groups.items() if len(g) > take[u]}
    while left > 0 and active:
        tw = sum(w[u] for u in active)
        full = [u for u in active if len(groups[u]) - take[u] <= left * w[u] / tw]
        if full:  # این منبع‌ها از سهمشون کوچیک‌ترن: کامل می‌شن و ظرفیتِ مونده بین بقیه پخش می‌شه
            for u in full:
                left -= len(groups[u]) - take[u]
                take[u] = len(groups[u])
                active.discard(u)
            continue
        base = {u: int(left * w[u] / tw) for u in active}
        for u, b in base.items():
            take[u] += b
        left -= sum(base.values())
        for u in sorted(active, key=lambda u: -w[u]):  # باقی‌مانده‌ی گرد کردن
            if left <= 0:
                break
            take[u] += 1
            left -= 1
        break
    out = []
    for u, g in groups.items():
        out.extend(g[:take[u]])
    random.shuffle(out)
    return out


def src_interleave(items, adj=None):
    """ترتیب تست: منبع‌های خوب سهم بیشتری از «اول صف» می‌گیرن، ولی هیچ منبعی کامل کنار گذاشته نمی‌شه.
    (ترتیب داخل هر منبع همون ترتیب قبلیه.) بدون این، منبع‌های غول‌پیکر منبع‌های کوچیکِ خوب رو پشت خودشون گم می‌کردن.
    adj(url): ضریب زنده از نتیجه‌ی همین اجرا (منبعی که همین الان سالم می‌ده >۱، منبعی که ده‌ها تست بی‌نتیجه داشته <۱)."""
    groups = {}
    for c in items:
        groups.setdefault(c.get("srcurl", ""), []).append(c)
    if len(groups) < 2:
        return list(items)
    keyed = []
    for gi, (u, g) in enumerate(groups.items()):
        w = max(0.008, src_score(u) * (adj(u) if adj else 1.0))
        for i, c in enumerate(g):
            keyed.append(((i + 0.5) / w, gi, i, c))
    keyed.sort(key=lambda x: x[:3])
    return [x[3] for x in keyed]


def learn_order(c):
    """کلید مرتب‌سازی: امیدوارکننده‌ترها اول. کمی تصادفی (حدود ±۲۵٪) تا برنامه همیشه چیزهای تازه رو هم امتحان کنه."""
    return -learn_score(c) * random.uniform(0.75, 1.25)


def _best_src():
    """نام منبع برتر برای نمایش؛ فقط منبع‌های عمومی (خودکار/پیش‌فرض)، نه لینک اشتراک شخصی که توکن داره."""
    try:
        best = None
        for x in load_db()["sources"]:
            v = LEARN["f"].get(_uk(x["url"]))
            if v and v[2] >= 3 and "token" not in x["url"].lower() and not urllib.parse.urlsplit(x["url"]).query:
                sc = (v[3] + 1) / (v[2] + 4)
                if sc > LEARN_PRIOR and (best is None or sc > best[0]):
                    best = (sc, x["url"])
        return [best[1]] if best else []
    except Exception:
        return []


def learn_summary():
    f = LEARN["f"]
    tot = lambda i: int(sum(v[i] for k, v in f.items() if k.startswith("p:")))
    if not f and not BAD["h"]:
        return None

    def best(prefix, n=1, min_site=5):
        rows = [(((v[3] + 1) / (v[2] + 4)), k[len(prefix):]) for k, v in f.items() if k.startswith(prefix) and v[2] >= min_site]
        return [x[1] for x in sorted(rows, reverse=True)[:n] if x[0] > LEARN_PRIOR]
    now = time.time()
    return dict(tested=tot(0), alive=tot(1), sitetested=tot(2), passed=tot(3), runs=LEARN["runs"],
                quarantined=sum(1 for v in BAD["h"].values() if v[0] > now), risky=risky_patterns(),
                proto=best("p:"), network=best("n:"), port=best("o:"), source=_best_src())


# ------------------------------------------------------------ حافظه‌ی «بد» (قرنطینه + امنیت)
# سرورهایی که خراب/بی‌فایده/خطرناک بودن مدتی از تست کنار گذاشته می‌شن؛ هر شکست بعدی مدت قرنطینه رو چند برابر می‌کنه.
# فقط هش (با نمک تصادفی همین نصب) ذخیره می‌شه، نه آدرس سرور. با بستن برنامه پاک نمی‌شه.
BAD_FILE = DATA / "bad.json"
BAD = {"salt": "", "h": {}}  # h[هش] = [تا چه زمانی، تعداد شکست پشت‌سرهم، نوع]
_bad_state = {"dirty": False, "saved": 0.0}
_bad_lock = threading.Lock()
BAD_HOURS = {"dead": (0, 6, 24, 72, 168), "sites": (0, 3, 12, 48, 168), "danger": (24, 720)}  # شکست اول قرنطینه نیست (کندی یا قطعی لحظه‌ای)؛ شکست پشت‌سرهم مدت رو بیشتر می‌کنه
BAD_EXPLORE = 0.05  # ۵٪ اوقات سرور قرنطینه‌شده (به‌جز خطرناک‌ها) دوباره امتحان می‌شه؛ شاید درست شده باشه


def bad_load():
    try:
        d = json.loads(BAD_FILE.read_text(encoding="utf-8"))
        BAD["salt"] = str(d.get("salt") or "")
        h = {}
        for k, v in (d.get("h") or {}).items():  # فایل دست‌کاری/خراب‌شده نباید قرنطینه‌ی دائمی یا کرش بسازه
            if (len(h) < 30000 and isinstance(v, list) and len(v) >= 3 and v[2] in BAD_HOURS
                    and isinstance(v[0], (int, float)) and not isinstance(v[0], bool) and math.isfinite(v[0]) and 0 <= v[0] <= 4e9
                    and isinstance(v[1], int) and not isinstance(v[1], bool) and 0 <= v[1] <= 1000 and re.fullmatch(r"[0-9a-f]{16}", str(k))):
                h[str(k)] = [float(v[0]), int(v[1]), str(v[2])]
        BAD["h"] = h
    except Exception:
        pass
    if not BAD["salt"]:
        BAD["salt"] = secrets.token_hex(8)


def bad_save(force=False):
    if not _bad_state["dirty"] or (not force and time.time() - _bad_state["saved"] < 30):
        return
    try:
        with _bad_lock:
            now = time.time()
            for k in [k for k, v in BAD["h"].items() if v[0] < now - 14 * 86400 and v[2] != "danger"]:
                del BAD["h"][k]
            if len(BAD["h"]) > 30000:
                for k in sorted(BAD["h"], key=lambda k: BAD["h"][k][0])[:len(BAD["h"]) - 30000]:
                    del BAD["h"][k]
            data = json.dumps(BAD, ensure_ascii=False)
            _bad_state.update(dirty=False, saved=now)
        DATA.mkdir(parents=True, exist_ok=True)
        _atomic(BAD_FILE, data)
    except Exception:
        pass


def bad_key(c, scoped=False):
    """scoped=True: کلید مخصوص «همین شبکه» (اپراتور/مودم) برای شکست‌های وابسته به شبکه (dead/sites)؛ «خطرناک» بودن ویژگی خود سروره و سراسریه."""
    ctx = f"|{NETID[0]}" if scoped and NETID[0] else ""
    # پشت CDN (SNI یا Host جدا از آدرس) هزاران سرور مستقل روی یک IP:پورت مشترکن؛ یک کانفیگ مرده یا مخرب نباید بقیه‌ی اون IP رو قرنطینه کنه
    fr = c.get("sni") or c.get("hosthdr") or ""
    front = f"|{c.get('sni') or ''}|{c.get('hosthdr') or ''}" if fr and fr != c.get("host") else ""
    raw = f"{BAD['salt']}|{c.get('host')}|{c.get('port')}|{c.get('proto')}{front}{ctx}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def bad_mark(c, kind):
    """یک شکست ثبت می‌کنه (kind: dead | sites | danger)."""
    try:
        k, now = bad_key(c, kind != "danger"), time.time()
        with _bad_lock:
            e = BAD["h"].get(k)
            strikes = (e[1] if e and (e[2] != "danger" or kind == "danger") else 0) + 1
            hrs = BAD_HOURS[kind]
            BAD["h"][k] = [now + hrs[min(strikes, len(hrs)) - 1] * 3600, strikes, kind]
            _bad_state["dirty"] = True
        bad_save()
    except Exception:
        pass


def bad_clear(c, *kinds):
    """سرور این بار خوب بود؛ شکست‌های قبلیِ این نوع بخشیده می‌شن (خطرناک‌ها هیچ‌وقت بخشیده نمی‌شن)."""
    try:
        k = bad_key(c, True)
        with _bad_lock:
            e = BAD["h"].get(k)
            if e and e[2] in kinds:
                del BAD["h"][k]
                _bad_state["dirty"] = True
    except Exception:
        pass


def bad_skip(c):
    """این سرور الان در قرنطینه‌ست؟ (خطرناک‌ها همیشه؛ بقیه به‌جز ۵٪ اکتشاف)"""
    now = time.time()
    g = BAD["h"].get(bad_key(c))
    if g and g[2] == "danger" and now < g[0]:
        return True  # خطرناک: سراسری، بدون اکتشاف
    e = BAD["h"].get(bad_key(c, True))  # مرده/سایت‌ها: فقط برای همین شبکه (روی مودم مرده بود، روی نت همراه شاید نه)
    if not e or e[2] == "danger" or now >= e[0]:
        return False
    return random.random() > BAD_EXPLORE


def _commit_bad(pend):
    """نتیجه‌ی یک اسکن کامل رو در حافظه‌ی بد ثبت می‌کنه، به‌جز وقتی خود شبکه مشکوک بوده:
    اسکن لغوشده؛ هیچ سروری جواب نداده (قطعی اینترنت یا فیلتر کامل، نه ۴۰ سرور خراب هم‌زمان)؛ یا بیشتر سرورها «خطرناک» شدن
    (شبکه‌ی دستکاری‌کننده یا پورتال ورود، نه صدها سرور مخرب). در این حالت‌ها هیچ سروری به‌خاطر این اسکن بد حساب نمی‌شه."""
    try:
        n = len(pend)
        if STOP.is_set() or n == 0:
            return
        ok = sum(1 for _, k in pend if k == "ok")
        dang = sum(1 for _, k in pend if k == "danger")
        outage = ok == 0 and n >= 5
        interference = dang >= 10 and dang / n > 0.5
        for c, k in pend:
            if k == "ok":
                bad_clear(c, "dead")
                sec_record(c, False)
            elif k == "danger" and not interference:
                bad_mark(c, "danger")
                sec_record(c, True)
            elif k == "dead" and not outage:
                bad_mark(c, "dead")
    except Exception:
        pass


_SEC_SEEN = set()
_SEC_SRC = {}


def sec_record(c, dangerous):
    """نتیجه‌ی تست امنیتی یک سرور سالم رو به ویژگی‌هاش (پروتکل، ترنسپورت، پورت، منبع) نسبت می‌ده."""
    try:
        with _learn_lock:
            who = (c.get("sni") or c.get("hosthdr") or c.get("host") or "", int(time.time() // 86400))
            if who in _SEC_SEEN:  # هر دامنه/سرور در روز فقط یک بار؛ هزار پورت یک سرور مخرب، ریسکِ عمومی پروتکل رو خراب نکنه
                return
            if len(_SEC_SEEN) > 50000:
                _SEC_SEEN.clear()
            _SEC_SEEN.add(who)
            sk = (str(c.get("srcurl") or ""), who[1])  # هر منبع در روز حداکثر ۵ «خطرناک» به ویژگی‌های عمومی (پروتکل، ترنسپورت، پورت) می‌دهد
            if len(_SEC_SRC) > 5000:
                _SEC_SRC.clear()
            _SEC_SRC[sk] = _SEC_SRC.get(sk, 0) + (1 if dangerous else 0)
            over = dangerous and bool(sk[0]) and _SEC_SRC[sk] > 5
            for k in learn_keys(c):
                if k.startswith("t:") or (over and not k.startswith("u:")):
                    continue
                v = LEARN["s"].setdefault(k, [0.0, 0.0])
                v[0] += 1
                v[1] += 1 if dangerous else 0
                if v[0] > 400:
                    v[:] = [x / 2 for x in v]
            _learn_state["dirty"] = True
        learn_save()
    except Exception:
        pass


FEAT_FA = {"p": "پروتکل", "n": "ترنسپورت", "s": "امنیت", "o": "پورت"}


def risky_patterns():
    """الگوهایی که خطرناک بودنشون به‌طور محسوس از میانگین کل بیشتره (نه ویژگی‌های عمومی که همه‌جا هستن)."""
    ot = sum(v[0] for k, v in LEARN["s"].items() if k.startswith("p:"))
    od = sum(v[1] for k, v in LEARN["s"].items() if k.startswith("p:"))
    base = max(0.15, 1.5 * od / (ot + 10))
    rows = []
    for k, v in LEARN["s"].items():
        if v[0] >= 10 and k[:2] in ("p:", "n:", "s:", "o:") and v[1] / (v[0] + 10) >= base:
            rows.append((v[1] / (v[0] + 10), f"{FEAT_FA[k[0]]} {k[2:] if k[2:] != 'other' else 'غیرمعمول'}"))
    return [r[1] for r in sorted(rows, reverse=True)[:3]]


learn_load()
bad_load()



# ------------------------------------------------------------ جستجوی خودکار منبع
AUTO_MAX = 25                        # حداکثر منبع خودکار
DISC_EVERY, DISC_RETRY = 12 * 3600, 3600
DISC = {"t": 0, "msg": "", "added": 0, "running": False}
_disc_lock = threading.Lock()


def source_v(url):
    return LEARN["f"].get(_uk(url))


def source_yield(url):
    """کیفیت یک منبع از تجربه‌ی خودمون: احتمال اینکه سرورش کار کنه × احتمال اینکه همه‌ی سایت‌ها رو باز کنه. بدون داده: خنثی."""
    v = source_v(url)
    return ((v[1] + 1) / (v[0] + 4) * (v[3] + 1) / (v[2] + 4)) if v else LEARN_PRIOR * LEARN_PRIOR


def discover_sources(force=False):
    """بعد از اتصال (از داخل تونل، چون api.github.com هم ممکنه فیلتر باشه) ریپوهای تازه‌ی گیت‌هاب رو می‌گرده.
    هر فایل کاندید جداگانه دانلود می‌شه و فقط اگه حداقل ۳۰ کانفیگ قابل‌خوندن داشته باشه به‌عنوان منبع خودکار اضافه می‌شه."""
    if not _disc_lock.acquire(blocking=False):
        return
    try:
        if not force and (load_settings().get("autosrc") is False or STOP.is_set()
                          or time.time() - LEARN["disc_t"] < (DISC_EVERY if LEARN["disc_ok"] else DISC_RETRY)):
            return
        DISC.update(running=True, msg="در حال جستجوی منبع تازه توی گیت‌هاب ...")
        ctx = cfgscan._ssl_ctx()
        direct, via = cfgscan._openers(ctx, HTTP if XRAY_PROC else None)
        urls, info = cfgscan.discover_github(via or direct, stop=STOP.is_set)
        have = {x["url"] for x in load_db()["sources"]} | set(load_db().get("removed", []))
        cand = [u for u in dict.fromkeys(urls) if u not in have][:12]
        added = 0
        for u in cand:
            if STOP.is_set():
                break
            links, _ = cfgscan.fetch_sources([u], per_source=3000, log=lambda m: None, stop=STOP.is_set,
                                             proxy_port=HTTP if XRAY_PROC else None, deadline=40)
            if len(links) >= 30:
                db = load_db()
                if u not in {x["url"] for x in db["sources"]}:
                    now = int(time.time())
                    db["sources"].append({"url": u, "on": True, "got": len(links), "alive": 0, "kind": "auto", "last_ok": now, "added": now})
                    save_db(db)
                    added += 1
        db = load_db()
        autos = [x for x in db["sources"] if x.get("kind") == "auto"]
        if len(autos) > AUTO_MAX:  # بدترین‌ها اول حذف می‌شن (و دوباره پیشنهاد نمی‌شن)
            for x in sorted(autos, key=lambda x: source_yield(x["url"]))[:len(autos) - AUTO_MAX]:
                db["sources"].remove(x)
                db.setdefault("removed", []).append(x["url"])
            save_db(db)
        ok = not (info["rate"] and not urls) and not (info["err"] and not urls)
        LEARN["disc_t"], LEARN["disc_ok"] = time.time(), ok
        _learn_state["dirty"] = True
        learn_save(True)
        DISC.update(t=int(time.time()), added=added,
                    msg=(f"{added} منبع تازه اضافه شد ({len(urls)} فایل کاندید بررسی شد)." if ok else
                         ("محدودیت نرخ گیت‌هاب؛ یک ساعت دیگه دوباره امتحان می‌کنم." if info["rate"] else "به گیت‌هاب نرسیدم؛ یک ساعت دیگه دوباره امتحان می‌کنم.")))
    except Exception:
        LEARN["disc_t"], LEARN["disc_ok"] = time.time(), False
        DISC["msg"] = "جستجو با خطا تموم شد؛ بعداً دوباره امتحان می‌کنم."
    finally:
        DISC["running"] = False
        _disc_lock.release()


def prune_sources():
    """منبع خودکاری که کلی سرور ازش تست شده ولی هیچ‌وقت هیچ سروری که شرط سایت‌ها رو داشته باشه نداده، غیرفعال می‌شه.
    منبعی که خودکار غیرفعال شده بود بعد از ۱۴ روز یک شانس دوباره می‌گیره (با آمار صفر)؛ اگه باز هم بد بود دیگه برنمی‌گرده.
    منبع‌های خودت (پیش‌فرض، کانال، دستی) هیچ‌وقت خودکار غیرفعال نمی‌شن."""
    try:
        db, ch, now = load_db(), False, time.time()
        with _learn_lock:  # اگه تقریباً هیچ سروری از هیچ منبعی کار نمی‌کنه، مشکل از شبکه است (قطعی)، نه از منبع؛ منبع خاموش نشه
            ot = sum(v[0] for k, v in LEARN["f"].items() if k.startswith("p:"))
            oa = sum(v[1] for k, v in LEARN["f"].items() if k.startswith("p:"))
        net_down = ot >= 200 and oa / ot < 0.03
        for x in db["sources"]:
            if x.get("kind") == "auto" and not x.get("on") and x.get("auto_off") and not x.get("revived") \
                    and now - float(x.get("off_t") or now) > 14 * 86400:
                x["on"], x["revived"], ch = True, True, True
                with _learn_lock:
                    LEARN["f"].pop(_uk(x["url"]), None)
                _learn_state["dirty"] = True
                continue
            v = source_v(x["url"]) if x.get("kind") == "auto" and x.get("on") else None
            if v and not net_down and v[0] >= 200 and v[3] == 0 and v[1] / v[0] < 0.03:
                x["on"], x["auto_off"], x["off_t"], ch = False, True, now, True
        if ch:
            save_db(db)
    except Exception:
        pass


def sites_pick(found, cache):
    """سرورهای سالمی که واقعاً همه‌ی سایت‌های لازم رو باز می‌کنن (بهترین اول). سرورهای تازه همین‌جا تست می‌شن؛
    نتیجه‌ی ناموفق بعد از ۴ دقیقه دوباره امتحان می‌شه تا یک کندی لحظه‌ای سرور خوب رو برای همیشه رد نکنه."""
    now = time.time()
    fresh = [c for c in sorted(list(found), key=lambda c: (round(learn_order(c), 1), ping_key(c)))
             if c["raw"] not in cache or (not sites_ok(cache[c["raw"]]) and now - cache[c["raw"]].get("site_t", 0) > 240)][:8]
    if fresh:
        S.update(step=4, msg=f"تست دسترسی به یوتیوب، اینستاگرام و تلگرام روی {len(fresh)} سرور سالم ...")
        for c, r in zip(fresh, check_many(fresh, 1, 5, 8, sites=True)):
            r["site_t"] = now
            cache[c["raw"]] = r
            if r.get("alive"):
                learn_record(r, "site")
                if sites_ok(r):
                    bad_clear(r, "dead", "sites")
                else:
                    bad_mark(r, "sites")
    live_ = [r for r in list(cache.values()) if r.get("alive") and not danger(r)]
    return sorted([r for r in live_ if sites_ok(r)], key=lambda r: (-sites_score(r), ping_key(r)))[:8]


def _pull_candidates(found, tried, n):
    """نامزدهای تازه برای تست: اول سرورهای تست‌شده‌ی سالم، بعد (وقتی تموم شدن) از صف سرورهای هنوز تست‌نشده."""
    uniq = {}
    for c in list(found) + list(POOL["standby"]):
        if c["raw"] not in tried and not danger(c):
            uniq.setdefault(c["raw"], c)
    now = time.time()  # اول سرورهایی که تازه (کمتر از SITE_FRESH ثانیه پیش) هر سایت لازم رو باز کرده‌ن؛ جابه‌جایی وقتی یوتیوب افتاد سریع‌تر می‌شه
    cand = sorted(uniq.values(), key=lambda c: (not (sites_ok(c) and now - c.get("site_t", 0) < SITE_FRESH), rk(c)))[:n]
    if cand:
        return cand
    out = []
    for _ in range(40):
        if len(out) >= n:
            break
        try:
            c = POOL["backlog"].pop(0)
        except IndexError:
            break
        if c["raw"] in tried or danger(c):
            continue
        cfgscan.reach(c, 3)
        if c.get("reachable"):
            out.append(c)
    return out


GUARD_LOCK = threading.Lock()


def sites_guard(gen, profile, found):
    if not GUARD_LOCK.acquire(blocking=False):  # هم‌زمان فقط یک جستجو؛ جابه‌جایی‌های تکراری روی هم نیفتن
        return
    try:
        _sites_guard(gen, profile, found)
    finally:
        GUARD_LOCK.release()


@resilient
def sites_watch(gen, profile, found):
    """هر SITE_EVERY ثانیه (۶۰) دسترسی به سه سایت رو از داخل تونل دوباره چک می‌کنه. اگه سرور خوب بعداً خراب شد
    (مثلاً یوتیوب بسته شد) بعد از یک تأیید دوباره، خودش بدون دخالت تو سرور بهتری پیدا می‌کنه و جابه‌جا می‌شه.
    قبلاً این چک هر ۵ دقیقه بود و یوتیوبِ از کار افتاده تا ۵ دقیقه بی‌خبر می‌موند."""
    try:
        while True:
            for _ in range(SITE_EVERY // 5):
                if GEN[0] != gen or STOP.is_set():
                    return
                time.sleep(5)
            if bg_quiet():
                continue  # حالت تماس: چک سایت‌ها و کشف منبع ترافیک اضافه‌ست
            if S["stage"] == "connected" and not DISC["running"] and time.time() - LEARN["disc_t"] > 20:
                threading.Thread(target=discover_sources, daemon=True).start()  # اگه موعدش نشده باشه فوراً برمی‌گرده
            if S["stage"] != "connected" or not POOL["active"] or GUARD_LOCK.locked():
                continue  # وصل نیستیم، یا یک جستجوی جابه‌جایی همین الان در جریانه
            r = cfgscan.site_check(SOCKS, 5)
            POOL["sites"] = r
            if sites_ok({"sites": r}):
                continue
            T.evt("sites", f"چک دوره‌ای: {_closed(r)} از سرور فعلی باز نشد")
            T.incident("sites_closed", closed=_closed(r), **_inc_state())
            if not calm_ok():
                continue  # تازه جابه‌جا شده‌ایم یا در حالت نوسان‌گیریم؛ سرور کار می‌کنه، تماس رو قطع نکن
            bad_n = 1
            for _ in range(2):  # یک کندی یا خطای لحظه‌ای نباید جابه‌جایی بسازه؛ سه بار پشت‌سرهم (فاصله‌ی ~۸ ثانیه) باید خراب باشه
                time.sleep(8)
                if GEN[0] != gen or STOP.is_set():
                    return
                r = cfgscan.site_check(SOCKS, 5)
                POOL["sites"] = r
                if sites_ok({"sites": r}):
                    break
                bad_n += 1
            if bad_n >= 3:
                if MODE[0] == "off":  # «خاموش» یعنی هیچ جابه‌جایی خودکاری (حتی با بسته‌شدن سایت‌ها)؛ فقط خبر می‌دیم
                    S["note"] = "چند سایت از این سرور باز نمی‌شن؛ جابه‌جایی خودکار خاموشه و سرور عوض نشد."
                    continue
                sites_guard(gen, profile, found)
    except Exception:
        raise


def _sites_guard(gen, profile, found):
    """بعد از اتصال (مخصوصاً بعد از جابه‌جایی خودکار): اگه سرور فعلی همه‌ی سایت‌های لازم رو باز نمی‌کنه،
    خودش دنبال سروری می‌گرده که باز کنه و بهش می‌پره. چند دور تکرار می‌شه چون سرورهای تازه مدام اضافه می‌شن."""
    try:
        time.sleep(1.5)
        if GEN[0] != gen or STOP.is_set() or not POOL["active"]:
            return
        r = cfgscan.site_check(SOCKS, 5)
        POOL["sites"] = r
        if sites_ok({"sites": r}):
            return
        tried = {POOL["active"][0]["raw"]}
        for rnd in range(3):
            S["note"] = (f"این سرور {_closed(POOL['sites'])} رو باز نمی‌کنه؛ دارم سروری پیدا می‌کنم که {_want()} رو باز کنه ..."
                         if rnd == 0 else f"هنوز دنبال سروری می‌گردم که {_want()} رو باز کنه (دور {rnd + 1} از ۳) ...")
            t_end = time.time() + (75 if rnd == 0 else 60)
            while time.time() < t_end and GEN[0] == gen and not STOP.is_set():
                cand = _pull_candidates(found, tried, 8)
                if not cand:
                    time.sleep(3)
                    continue
                tried.update(c["raw"] for c in cand)
                good = [x for x in check_many(cand, 1, 5, 8, sites=True) if solid(x) and sites_ok(x)]
                if not good:
                    continue
                best = sorted(good, key=lambda x: (-sites_score(x), rk(x)))[0]
                with SWITCH:
                    if GEN[0] != gen or STOP.is_set():
                        return
                    prev = list(POOL["active"])
                    closed_txt = _closed(POOL.get("sites"))
                    sel = start_xray([best], profile)
                    ms = probe_retry(2, 3)
                    if not ms:
                        start_xray(prev, profile)
                        continue
                    set_active(sel, ms)
                    bench_add(prev)  # این سرور هنوز کار می‌کنه (فقط بعضی سایت‌ها نه)؛ دور ریخته نمی‌شه
                    POOL["switches"] += 1
                    POOL["sites"] = best["sites"]
                    save_good(sel)
                    sw_mark(f"سرور قبلی {closed_txt or 'بعضی سایت‌ها'} رو باز نمی‌کرد")
                S.update(msg="وصل شدی ✓", note=f"به سروری وصل شدی که {_want()} رو باز می‌کنه")
                return
            if rnd < 2:
                for _ in range(6):  # ۳۰ ثانیه صبر تا سرورهای تازه به صف اضافه بشن
                    if GEN[0] != gen or STOP.is_set():
                        return
                    time.sleep(5)
        if GEN[0] == gen and not STOP.is_set():
            S["note"] = (f"بین سرورهای تست‌شده هیچ‌کدوم {_want()} رو باز نکرد؛ فعلاً همین سرور فعاله. "
                         "چند ساعت بعد دوباره اسکن کن.")
    except Exception:
        pass


def standby_sites(gen):
    """جایگزین‌های آماده (بخش «سرورها») رو در پس‌زمینه از نظر سایت‌های لازم تست می‌کنه؛
    اونایی که باز نمی‌کنن از لیست جایگزین‌ها حذف می‌شن تا جابه‌جایی خودکار هیچ‌وقت به سرور بی‌فایده نپره."""
    try:
        while GEN[0] == gen and not STOP.is_set():
            if bg_quiet():
                time.sleep(5)  # حالت تماس: تست پس‌زمینه‌ی سایت‌ها ممنوع
                continue
            now = time.time()  # تازه‌ها یا اونایی که نتیجه‌ی سایتشون از SITE_RETEST ثانیه قدیمی‌تره (سرور وسط راه ممکنه خراب شده باشه)
            todo = sorted([c for c in list(POOL["standby"]) if "sites" not in c or now - c.get("site_t", 0) > SITE_RETEST],
                          key=lambda c: c.get("site_t", 0))[:6]
            if not todo:
                time.sleep(5)
                continue
            okl = []
            for o, r in zip(todo, check_many(todo, 1, 5, 6, sites=True)):
                if r.get("alive"):
                    learn_record(r, "site")
                    if not sites_ok(r):
                        bad_mark(r, "sites")
                o["site_t"] = time.time()
                if r.get("alive") and sites_ok(r):
                    o["sites"] = r["sites"]
                    okl.append(o)
                else:
                    o["sites"] = {}
                    try:
                        POOL["standby"].remove(o)
                    except ValueError:
                        pass
            if okl:
                save_good(okl)  # سرورهای تاییدشده یادشون می‌مونه؛ دفعه‌ی بعد اول همین‌ها تست می‌شن و اتصال خیلی سریع‌تره
    except Exception:
        pass


def record_channels(stats, n):
    """نتیجه‌ی دریافت دوباره‌ی کانال‌ها (از داخل تونل) رو توی همون جدول منابع می‌ذاره تا صفحه ✓ و ✗ درست نشون بده."""
    try:
        db = load_db()
        now = int(time.time())
        for x in db["sources"]:
            st = stats.get(x["url"])
            if not st:
                continue
            x["got"], x["err"] = st["got"], st.get("err", "")
            if st["got"]:
                x["last_ok"] = now
        save_db(db)
        on = [x for x in db["sources"] if x.get("on")]
        FETCHINFO.update(t=now, n=(FETCHINFO.get("n") or 0) + n, ok=sum(1 for x in on if x.get("got")), total=len(on))
    except Exception:
        pass


def channels_retry(gen, profile, seen):
    """کانال‌های تلگرام معمولاً بدون تونل باز نمی‌شن. بعد از وصل شدن، اونایی که خالی موندن رو از داخل تونل دوباره می‌خونه و کانفیگ‌هاشون رو به صف تست اضافه می‌کنه."""
    try:
        P = cfgforge.PROFILES[profile]
        for rnd in range(4):
            for _ in range(3 if rnd == 0 else 12):
                if GEN[0] != gen or STOP.is_set():
                    return
                time.sleep(5)
            while S["stage"] != "connected" or not XRAY_PROC:
                if GEN[0] != gen or STOP.is_set():
                    return
                time.sleep(5)
            bad = [x["url"] for x in load_db()["sources"] if x.get("kind") == "channel" and x.get("on") and not x.get("got")]
            if not bad:
                return
            links, stats = cfgscan.fetch_sources(bad, per_source=800, log=lambda m: None, stop=STOP.is_set,
                                                 proxy_port=HTTP, deadline=70)
            record_channels(stats, len(links))
            random.shuffle(links)
            for l in links:
                if l in seen:
                    continue
                seen.add(l)
                c = cfgscan.parse(l)
                if c and cfgscan.ckey(c) not in seen:
                    seen.add(cfgscan.ckey(c))
                    cfgscan.static(c)
                    if not ("unsupported" in c["flags"] or "private_addr" in c["flags"] or danger(c)
                            or not usable(c, P["only_encrypted"]) or (P["only_encrypted"] and c["flags"] & STRICT_BAD)):
                        POOL["backlog"].append(c)
    except Exception:
        pass


def probe_robust(timeout=3.0):
    """تست سلامت تونل با دو آدرس مختلف و تایم‌اوت بلندتر؛ یه کندی لحظه‌ای نباید به‌عنوان قطع حساب بشه."""
    for u in random.sample(PROBES, min(2, len(PROBES))):
        try:
            st, _, ms = cfgscan.fetch(SOCKS, u, timeout)
            if st in (204, 200):
                return ms
        except Exception:
            pass
    return None


def net_up():
    """اینترنت خود کاربر (بدون تونل) وصله؟ اگه نه، عوض‌کردن سرور فایده‌ای نداره و سرورها بی‌خود خراب حساب نمی‌شن."""
    ok = threading.Event()

    def one(h, p):
        try:
            socket.create_connection((h, p), 2.5).close()
            ok.set()
        except OSError:
            pass
    for h, p in (("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443), ("208.67.222.222", 443), ("www.msftconnecttest.com", 80)):
        threading.Thread(target=one, args=(h, p), daemon=True).start()
    ok.wait(3.0)
    return ok.is_set()


def startup_refresh():
    """اولین بار بعد از باز شدن برنامه: فهرست سیاه و منابع رو تازه می‌کنه (بدون منتظر موندن برای دکمه‌ی شروع)."""
    PREFETCH_RUNNING[0] = True
    try:
        say("در حال به‌روزرسانی منابع و فهرست سیاه ...")
        tb = threading.Thread(target=update_block, args=(True,), daemon=True)
        tb.start()
        if save_net_now() and _age_h(DATA / "cache.txt") < 6:
            say("صرفه‌جویی اینترنت: فهرست کانفیگ‌ها کمتر از ۶ ساعت پیش دانلود شده؛ الان دوباره دانلود نمی‌شه (هر وقت لازم بود خودش تازه می‌کنه).")
            tb.join(30)
            return
        ca = HERE / "cacert.pem"
        if ca.is_file():
            cfgscan.CA_FILE = str(ca)
        urls = [x["url"] for x in load_db()["sources"] if x["on"]]
        org = {}
        links, stats = cfgscan.fetch_sources(urls, per_source=2500, log=lambda m: None, origin=org, stop=STOP.is_set)
        if links:
            random.shuffle(links)
            PREFETCH.update(links=links, stats=stats, t=time.time(), origin=org)
            if len(links) >= 50:
                try:
                    write_secret(DATA / "cache.txt", "\n".join(balance_links(links, org)))
                except OSError:
                    pass
            say(f"منابع به‌روز شد: {len(links)} کانفیگ تازه.")
        else:
            say(f"به‌روزرسانی منابع ناموفق بود ({cfgscan.why_text(stats)}). موقع جستجو دوباره امتحان می‌شه.")
        record_fetch(stats, len(links))
        tb.join(90)
    except Exception as e:
        say(f"خطا در به‌روزرسانی اولیه: {type(e).__name__}")
    finally:
        PREFETCH_RUNNING[0] = False
        PREFETCH_EVT.set()


def daily_refresh():
    while True:
        time.sleep(86400)
        update_block(True)


LASTARGS = [None]  # (profile, sysproxy, mode) آخرین اجرا؛ برای شروع دوباره‌ی جستجو بعد از عوض شدن شبکه


def _netid(asn, kd):
    """شناسه‌ی شبکه برای یادگیری جدا: اپراتور + نوع اتصال. اگه هیچ‌کدوم مشخص نبود خالیه (یعنی یادگیریِ جدا نداریم)."""
    return "a:" + hashlib.sha256(((asn or "") + "|" + (kd or "")).encode()).hexdigest()[:10] if (asn or kd) else ""


def reprobe_net():
    """سنجش دوباره‌ی شبکه‌ی فعلی (بعد از عوض شدن شبکه)، بدون دست زدن به اتصال."""
    try:
        if netprobe is None or os.environ.get("CFG_NETPROBE") == "0" or load_settings().get("netprobe") is False:
            return
        kd = netprobe.net_kind()
        r = netprobe.probe(STOP.is_set)
        if isinstance(r, dict):
            r["kind"] = kd
        NETP["shown"] = r
        if r and r.get("net_ok"):
            NETP["net"] = r
            NETID[0] = _netid(r.get("asn"), kd)
            say("شبکه عوض شد. " + netprobe.summary_fa(r))
    except Exception:
        pass


NETCHG = {"n": 0, "t": 0.0, "log": deque(maxlen=12)}
RESTART_T = [0.0]
FA_NET = {"mob": "نت همراه", "wifi": "وای‌فای", "eth": "کابل/مودم", "": "نامشخص"}


def _fa_net(fp):
    k = (fp or "").split("#")[0].split(":")[0]
    return FA_NET.get(k, "شبکه‌ی دیگه")


def restart_pipeline(reason):
    """جستجو/اتصال رو با همون تنظیمات آخر از نو شروع می‌کنه (مثلاً بعد از عوض شدن شبکه)؛ نتیجه‌ی تست‌های شبکه‌ی قبلی دیگه معتبر نیست."""
    global PIPE
    if not LASTARGS[0] or QUITTING[0]:
        return False
    if time.time() - RESTART_T[0] < 15:  # شبکه مدام قطع‌ووصل می‌شه؛ هر چند ثانیه از نو شروع نکن (پیشرفت جستجو هدر نره)
        T.evt("restart_skipped", reason)
        return False
    RESTART_T[0] = time.time()
    prof, sysproxy, mode = LASTARGS[0]
    with START_LOCK:
        if PIPE and PIPE.is_alive():
            STOP.set()
            PIPE.join(20)
        if PIPE and PIPE.is_alive():
            return False
        SITE_CACHE.clear()
        POOL["tiers"] = None
        PREFETCH.update(links=[], stats={}, t=0.0, origin={})
        cfgscan.REACH_CACHE.clear()
        T.evt("restart", reason)
        PIPE = threading.Thread(target=pipeline, args=(prof, True, sysproxy, mode, True), daemon=True)
        PIPE.start()
    return True


def on_net_change(old, new):
    """شبکه عوض شد (نت همراه ↔ وای‌فای ↔ مودم، یا اپراتور/سیم‌کارت/وای‌فای دیگه): فوری واکنش نشون بده."""
    NETCHG["n"] += 1
    NETCHG["t"] = time.time()
    NETCHG["log"].append([time.strftime("%H:%M:%S"), _fa_net(old), _fa_net(new), S.get("stage", "")])
    T.evt("net_change", f"شبکه عوض شد: {_fa_net(old)} ← {_fa_net(new)} (مرحله: {S.get('stage')})")
    T.incident("net_change", was=(old or "").split("#")[0], now=(new or "").split("#")[0], **_inc_state())
    NETP["net"], NETID[0] = None, ""
    S["netchg"] = {"t": int(time.time()), "from": _fa_net(old), "to": _fa_net(new)}
    say(f"شبکه عوض شد: {_fa_net(old)} ← {_fa_net(new)}")
    stage = S.get("stage")
    if stage == "running":  # وسط جستجو: نتیجه‌ی تست‌های قبلی مال شبکه‌ی دیگه‌ست؛ از نو با شبکه‌ی جدید
        S["note"] = f"شبکه عوض شد ({_fa_net(old)} ← {_fa_net(new)}); جستجو رو با شبکه‌ی جدید از نو شروع می‌کنم ..."
        restart_pipeline("تغییر شبکه وسط جستجو")
        return
    if stage == "connected":
        S["note"] = f"شبکه عوض شد ({_fa_net(old)} ← {_fa_net(new)}); دارم سرور فعلی رو روی شبکه‌ی جدید می‌سنجم ..."
        ok = bool(probe(3.0)) or bool(probe(3.0))
        if not ok:
            S["note"] = "شبکه عوض شد و سرور فعلی روی این شبکه جواب نمی‌ده؛ دوباره جستجو می‌کنم ..."
            restart_pipeline("سرور فعلی روی شبکه‌ی جدید جواب نداد")
            return
        S["note"] = "شبکه عوض شد؛ سرور فعلی روی شبکه‌ی جدید هم جواب می‌ده."
        threading.Thread(target=reprobe_net, daemon=True).start()
        gen = GEN[0]
        threading.Thread(target=refresh_standby, args=(gen,), daemon=True).start()  # جایگزین‌ها هم روی شبکه‌ی جدید دوباره سنجیده می‌شن
        threading.Thread(target=sites_guard, args=(gen, CUR[0], []), daemon=True).start()
        return
    threading.Thread(target=reprobe_net, daemon=True).start()


def net_watch():
    """هر ۳ ثانیه (بدون ترافیک) اثرانگشت شبکه رو می‌سنجه. دو نمونه‌ی پشت‌سرهم با مقدار تازه یعنی واقعاً عوض شده (≈۶ ثانیه)."""
    last = pend = None
    n = 0
    while True:
        time.sleep(3)
        try:
            cfgdata.save()
            if netprobe is None:
                continue
            fp = netprobe.net_fp()
            if not fp:
                continue
            if last is None:
                last = fp
                continue
            if fp == last:
                pend, n = None, 0
                continue
            if fp != pend:
                pend, n = fp, 1
                continue
            n += 1
            if n < 2:
                continue
            old, last, pend, n = last, fp, None, 0
            on_net_change(old, fp)
        except Exception as e:
            T.err("net_watch", e)


def pipeline(profile, quick, sysproxy, failover_on="stable", auto=False, level=1, cycle=0):
    mode = failover_on if failover_on in ("stable", "fast", "off") else ("stable" if failover_on else "off")
    failover_on = mode != "off"
    LASTARGS[0] = (profile, sysproxy, mode)
    held = [False]
    pend = []  # نتیجه‌ی تست‌ها برای ثبت در حافظه‌ی «بد»، آخر اسکن
    RUNNING[0] += 1
    try:
        STOP.clear()
        cfgscan.REACH_CACHE.clear()
        AVF[0], lbn = 1.0, [0, 0]  # lbn: [بسته‌شده توسط دستگاه، کل تلاش‌های اتصال]
        T.run_begin(level=level, cycle=cycle, quick=bool(quick), profile=profile, speed=eff_speed(), auto=bool(auto), call=bool(CALL[0]))
        T.evt("search", f"شروع جستجو: مرحله {level}، دور {cycle}، {'سریع' if quick else 'کامل'}، سرعت {eff_speed()}، حالت {profile}")
        disconnect(silent=True, keep_proxy=auto)
        GEN[0] += 1
        if level == 1 and cycle == 0:
            RUN.clear()
            RUN.update(report.new_stats())
        S.update(stage="running", step=1, pct=3, connected=None, note=S.get("note", "") if auto else "",
                 msg="در حال جستجو ..." if level == 1 else f"وصل نشد؛ تلاش با روش‌های قوی‌تر (مرحله {level}) ...")
        xray = find_xray()
        cfgscan.SINGBOX = find_singbox()
        if not xray:
            raise RuntimeError("فایل xray کنار برنامه پیدا نشد.")
        db = load_db()
        urls = [s["url"] for s in db["sources"] if s["on"]]
        P = cfgforge.PROFILES[profile]
        CUR[0] = profile
        target, up_cap, hard_cap = (14, 90, 360) if quick else (24, 240, 900)
        if net_is_mobile():  # نت همراه: بعد از چند سرور سالمِ کافی جستجو رو تموم کن؛ هر تست چند کیلوبایت از بسته‌ی نت می‌خوره
            target, up_cap = min(target, 6), min(up_cap, 45)
        if profile in SPEEDLIKE:  # برای پیدا کردن سرور واقعاً سریع، نمونه‌ی بیشتری لازمه
            target, up_cap = max(target, 24), max(up_cap, 150)
        tmo = [2.5, 5] if level == 1 else [4, 9]
        if level >= 2:
            hard_cap *= 2
        seen, cands, origin, fst = set(), [], {}, {"n": 0}
        sp = speed_params()
        q, sem, lock, pend, blk = queue.Queue(), DynLimit(lambda: speed_params()["live"]), threading.Lock(), [0], [0]
        skip = {"unsupported": 0, "insecure": 0}
        todo, todo_lock, mst, sst, picks = [], threading.Lock(), {}, {}, [0]  # صف زنده: هر تست وقتی نوبتش شد «بهترینِ فعلی» رو برمی‌داره (نه ترتیبِ اولِ جستجو)
        DIAG.update(tested=0, ok=0, no_reach=0, no_traffic=0, unsafe=0, skip=skip)
        pace = Pace(lambda: speed_params()["rate"] * (1 if level == 1 else 2) * AVF[0])
        ex = ThreadPoolExecutor(max_workers=sp["workers"])
        found, connected, fails, t0, t_first = [], [False], [0], time.time(), [None]

        def smsg(sub=""):
            """یک پیام ثابت و پراطلاعات برای جستجو (شمارنده‌ها همیشه همون‌جا می‌مونن؛ فقط توضیح مرحله‌ی فرعی عوض می‌شه)،
            تا صفحه بین چند متن مختلف نپره و کاربر ببینه واقعاً چقدر پیش رفته."""
            el = max(1, int(time.time() - t0))
            tot, fin = max(pend[0], 1), finished
            S["prog"] = {"tested": fin, "total": tot, "alive": len(found), "elapsed": el, "cap": hard_cap, "rate": round(fin / el, 1)}
            m = f"در حال جستجو: {fin} از {tot} تست شد · {len(found)} سالم · {round(fin / el, 1)} تست در ثانیه · {el // 60}:{el % 60:02d} از {hard_cap // 60}:00"
            if sub == "check":
                m += " — دارم یوتیوب، اینستاگرام و تلگرام رو روی یک سرور سالم می‌سنجم"
            elif sub == "none" and found:
                m += f" — هنوز سروری که {_want()} رو باز کنه پیدا نشده؛ جستجو ادامه داره"
            return m
        fetch_done = threading.Event()
        net, net_evt, clock = [None], threading.Event(), [False]
        NETID[0] = ""  # شبکه‌ی این اجرا هنوز مشخص نیست (ممکنه سیم‌کارت/مودم عوض شده باشه)
        if level == 1 and cycle == 0:
            S["warn"] = ""

        def probe_net():
            """شبکه رو می‌سنجه (کدوم پورت/UDP/QUIC/فیلتر SNI/ساعت). فقط ترتیب و حذف‌های «قطعی» رو تغییر می‌ده؛ نتیجه‌ی نامطمئن (unknown) هیچ اثری نداره."""
            try:
                if netprobe is None or os.environ.get("CFG_NETPROBE") == "0" or load_settings().get("netprobe") is False:
                    return
                try:  # نوع اتصال (مودم / نت همراه / هات‌اسپات)؛ سنجشِ یک شبکه هیچ‌وقت برای شبکه‌ی دیگه استفاده نمی‌شه
                    kd = netprobe.net_kind()
                except Exception:
                    kd = ""
                old = NETP["net"]
                same = bool(old) and (old.get("kind", "") == kd)
                r = old if (same and level == 1 and time.time() - old["t"] < 120) else netprobe.probe(STOP.is_set)
                if isinstance(r, dict):
                    r["kind"] = kd
                NETP["shown"] = r
                if not r or not r.get("net_ok"):
                    return
                NETP["net"], net[0] = r, r
                NETID[0] = _netid(r.get("asn"), kd)
                T.run_mark("net_probe", net=kd or "?", probe_s=r.get("dur"))
                sc = netprobe.timeout_scale(r)
                if sc > 1:
                    tmo[0], tmo[1] = min(tmo[0] * sc, 9), min(tmo[1] * sc, 18)
                say(netprobe.summary_fa(r))
                if netprobe.clock_bad(r):
                    clock[0] = True
                    S["warn"] = netprobe.clock_msg_fa(r)
                    say(S["warn"])
            except Exception:
                pass
            finally:
                net_evt.set()

        threading.Thread(target=probe_net, daemon=True).start()

        def work(c):
            try:
                if STOP.is_set():
                    return
                ta = time.time()
                pace.wait()
                tb = time.time()
                T.perf("pace_wait_s", tb - ta)  # انتظار برای سقف نرخ اتصال
                cfgscan.reach(c, tmo[0])
                T.perf("reach_s", time.time() - tb)  # DNS + اتصال TCP
                lbn[1] += 1
                if "local_block" in c["flags"]:  # آنتی‌ویروس/فایروالِ همین دستگاه بست: نه خرابیِ سرور، نه موضوع یادگیری/قرنطینه
                    lbn[0] += 1
                    DIAG["local_block"] = lbn[0]
                    c["tested"], c["alive"] = False, False
                    if lbn[0] in (5, 25, 100):
                        _av_note(lbn)
                    return
                if "blocklisted" in c["flags"]:
                    blk[0] += 1
                    S["blocked"] = blk[0]
                if not c.get("reachable") or "private_addr" in c["flags"]:
                    c["tested"], c["alive"] = True, False
                    return
                T.run_mark("first_reach")
                tc = time.time()
                with sem:
                    td = time.time()
                    T.perf("slot_wait_s", td - tc)  # انتظار برای یکی از جای‌های «تست هم‌زمان» (گلوگاهِ واقعیِ سرعت)
                    if STOP.is_set():
                        return
                    try:
                        cfgscan.live(c, xray, 1, tmo[1])
                    except Exception as e:
                        c["alive"] = False
                        c["fail"] = "exception"
                        T.err("live", e)
                    T.perf("live_ok_s" if c.get("alive") else "live_dead_s", time.time() - td)  # یک تست زنده (xray + درخواست) چقدر طول کشید
                    if level >= 2 and not c.get("alive") and c["security"] in ("tls", "reality") and not STOP.is_set():
                        try_variants(c, xray, tmo[1])
                c["tested"] = True
            finally:
                if c.get("tested"):
                    if c.get("alive"):
                        T.run_mark("first_alive")
                    T.count("test_total")
                    T.count("why:" + ("ok" if c.get("alive") else c.get("fail") or ("no_reach" if not c.get("reachable") else "unknown")))
                    m = mst.setdefault(_mkey(c), [0, 0])
                    m[0] += 1
                    m[1] += 1 if c.get("alive") else 0
                    if c.get("src") == "net":  # نتیجه‌ی زنده‌ی هر «منبع» در همین اجرا (برای سهم‌دهیِ دوباره‌ی منبع‌ها)
                        sm = sst.setdefault(c.get("srcurl", ""), [0, 0])
                        sm[0] += 1
                        sm[1] += 1 if c.get("alive") else 0
                    DIAG["tested"] += 1
                    DIAG["no_reach" if not c.get("reachable") else "unsafe" if danger(c) else "ok" if c.get("alive") else "no_traffic"] += 1
                if c.get("tested") and not clock[0]:  # ساعت غلط = نتیجه‌ی تست قابل‌اعتماد نیست؛ چیزی یاد گرفته/قرنطینه نشه
                    learn_record(c, "live")
                    # نتیجه فقط جمع می‌شه؛ آخر اسکن و فقط اگه شبکه سالم بوده ثبت می‌شه (_commit_bad). قطعی اینترنت یا شبکه‌ی دستکاری‌کننده
                    # نباید سرورهای سالم رو قرنطینه کنه.
                    pend.append((c, "danger" if danger(c) else "ok" if c.get("alive") else "dead"))
                q.put(c)

        def _rank(c):
            return {"custom": 0, "good": 1, "cache": 3, "snap": 3}.get(c.get("src"), 2)

        def _resort():
            """هر چند تست، باقی‌مانده‌ی صف دوباره مرتب می‌شه. روشی که توی همین اجرا و همین شبکه ده‌ها بار تست شده و هیچ سالمی نداده عقب می‌ره (حذف نمی‌شه)،
            روشی که خوب جواب داده جلو می‌آد. بدون این، ترتیبِ اولِ جستجو تا آخر ثابت می‌موند، حتی وقتی معلوم شده بود نصف صف بی‌فایده‌ست."""
            tot, ok = sum(v[0] for v in mst.values()), sum(v[1] for v in mst.values())
            base = (ok + 0.3) / (tot + 3)
            nt = net[0]

            def adj(c):
                m = mst.get(_mkey(c))
                if not m or m[0] < 30:
                    return 1.0
                r = min(6.0, max(0.05, ((m[1] + 0.3) / (m[0] + 3)) / base))
                return 1.0 + (r - 1.0) * min(1.0, m[0] / 60.0)
            stot, sok = sum(v[0] for v in sst.values()), sum(v[1] for v in sst.values())
            sbase = (sok + 0.3) / (stot + 3)

            def sadj(u):
                """ضریب زنده‌ی منبع: نرخ سالمِ همین منبع در همین اجرا نسبت به میانگین همه (با شِرینکیج؛ تا ۲۰ تست اثری نداره)."""
                m = sst.get(u)
                if not m or m[0] < 20:
                    return 1.0
                r = min(8.0, max(0.1, ((m[1] + 0.3) / (m[0] + 3)) / sbase))
                return 1.0 + (r - 1.0) * min(1.0, m[0] / 80.0)
            items = list(todo)
            items.sort(key=lambda c: (_rank(c), "no_tls" in c["flags"], netprobe.priority(c, nt) if nt else 0,
                                      -learn_score(c) * adj(c) * random.uniform(0.75, 1.25)))
            todo[:] = [c for c in items if _rank(c) < 2] + src_interleave([c for c in items if _rank(c) == 2], sadj) + [c for c in items if _rank(c) > 2]

        def ticket():
            with todo_lock:
                if not todo:
                    return
                picks[0] += 1
                if picks[0] % 60 == 1 and len(todo) > 1:
                    try:
                        _resort()
                    except Exception:
                        pass
                c = todo.pop(0)
            work(c)

        add_lock, old_lock, old_added, ended = threading.Lock(), threading.Lock(), [False], [False]

        def add(links, tag="net"):
            with add_lock:
                _add(links, tag)

        def _add(links, tag):
            if STOP.is_set() or ended[0]:
                return
            if tag in ("net", "cache", "snap"):
                net_evt.wait(6)  # لیست‌های بزرگ بعد از سنجش شبکه مرتب می‌شن؛ حداکثر ۶ ثانیه صبر
            nt = net[0]
            parsed = []
            for l in links:
                if l in seen:
                    continue
                seen.add(l)
                c = cfgscan.parse(l)
                if not c:
                    continue
                k = cfgscan.ckey(c)  # همان سرور با #remark یا ترتیب پارامتر متفاوت، دوباره تست نشه
                if k in seen:
                    continue
                seen.add(k)
                cfgscan.static(c)
                c["src"] = tag
                c["srcurl"] = origin.get(l, "") if tag == "net" else ""
                if "blocklisted" in c["flags"]:
                    blk[0] += 1
                    continue
                if "unsupported" in c["flags"]:
                    skip["unsupported"] += 1
                    continue
                if tag != "custom" and bad_skip(c):  # در قرنطینه (خراب یا خطرناک بوده)؛ سرورهای دستیِ خودت هیچ‌وقت رد نمی‌شن
                    skip["quarantine"] = skip.get("quarantine", 0) + 1
                    continue
                if "insecure_cert" in c["flags"]:
                    skip["insecure"] += 1
                    continue
                if nt and level == 1 and tag != "custom" and netprobe.hard_skip(c, nt):  # فقط وقتی UDP با چند مقصد مستقل «قطعاً بسته» ثابت شده
                    skip["udp_dead"] = skip.get("udp_dead", 0) + 1
                    continue
                if nt and netprobe.want_frag(c, nt):
                    c["frag"] = True
                if ("private_addr" in c["flags"] or danger(c)
                        or not usable(c, P["only_encrypted"])
                        or (P["only_encrypted"] and c["flags"] & STRICT_BAD)):
                    continue
                parsed.append(c)
            parsed.sort(key=lambda c: ("no_tls" in c["flags"], netprobe.priority(c, nt) if nt else 0, learn_order(c)))  # امیدوارکننده‌ترها (طبق تجربه‌ی قبلی) اول تست می‌شن
            parsed = src_interleave(parsed)  # منبع‌های خوب جلوترن ولی منبع غول‌پیکر بقیه رو دفن نمی‌کنه
            for c in parsed:
                cands.append(c)
                if ended[0]:
                    return
                with lock:
                    pend[0] += 1
                with todo_lock:
                    todo.append(c)
                try:
                    ex.submit(ticket)
                except RuntimeError:  # جستجو همین الان تموم شد
                    return

        add(read_links(DATA / "custom.txt"), "custom")  # اولویت: دستی، سالم‌های قبلی، بعد لیست‌های تازه‌دانلودشده
        add(read_links(DATA / "good.txt"), "good")

        def add_old():  # آخرین دانلود قبلی و بسته‌ی همراه: فقط بعد از تازه‌ها، تا تازه‌ها پشت هزاران کانفیگ قدیمی صف نکشن
            with old_lock:
                if old_added[0]:
                    return
                old_added[0] = True
            add(read_links(DATA / "cache.txt"), "cache")
            add(read_links(HERE / "snapshot.txt"), "snap")

        old_timer = threading.Timer(12, add_old)  # اگه دانلود طولانی شد، قدیمی‌ها بیکار نمونن
        old_timer.daemon = True
        old_timer.start()

        def fetcher():
            try:
                ca = HERE / "cacert.pem"
                if ca.is_file():
                    cfgscan.CA_FILE = str(ca)
                links, stats = [], {}
                if PREFETCH_RUNNING[0] and not PREFETCH_EVT.is_set():
                    PREFETCH_EVT.wait(20)  # به‌روزرسانی اولیه‌ی برنامه هنوز در حال انجامه؛ همونو استفاده کن
                if PREFETCH["links"] and time.time() - PREFETCH["t"] < 900 and not STOP.is_set():
                    links, stats = list(PREFETCH["links"]), PREFETCH["stats"]
                    origin.update(PREFETCH["origin"])
                    say(f"از منابع تازه‌ی همین چند لحظه‌ی پیش استفاده می‌شه ({len(links)} کانفیگ).")
                skip = (save_net_now() and _age_h(DATA / "cache.txt") < 6 and level == 1 and not links)  # نت همراه: لیست تازه‌ی ۶ ساعته هست؛ دوباره دانلود نکن
                if skip:
                    say("صرفه‌جویی اینترنت: از فهرست کانفیگ‌های ذخیره‌شده (کمتر از ۶ ساعت) استفاده می‌شه.")
                for n in (1, 2, 3):
                    if links or skip:
                        break
                    links, stats = cfgscan.fetch_sources(urls, per_source=2500, log=say, origin=origin, stop=STOP.is_set,
                                                         proxy_port=HTTP if XRAY_PROC else None)
                    if links or STOP.is_set() or n == 3:
                        break
                    say(f"دانلود لیست‌ها ناموفق بود (علت اصلی: {cfgscan.why_text(stats)}). "
                        "صبر می‌کنم تا یک سرور وصل بشه و دوباره از مسیر اون امتحان می‌کنم.")
                    t_end = time.time() + 45
                    while time.time() < t_end and not STOP.is_set() and not XRAY_PROC:
                        time.sleep(1)
                for s in db["sources"]:
                    if s["url"] in stats:
                        s["got"], s["alive"] = stats[s["url"]]["got"], 0
                fst["n"] = len(links)
                if stats and stats is not PREFETCH["stats"]:
                    record_fetch(stats, len(links))
                if links:
                    links = balance_links(links, origin)  # بریدن به سقف بدون ریختن منبع‌های کوچیکِ خوب؛ ترتیب خروجی تصادفی
                    if len(links) >= 50:
                        try:
                            write_secret(DATA / "cache.txt", "\n".join(links))
                        except OSError:
                            pass
                elif not skip:
                    try:
                        age = int((time.time() - (DATA / "cache.txt").stat().st_mtime) / 3600)
                        old = f"آخرین دانلود موفق {age} ساعت پیش بود" if age else "آخرین دانلود موفق کمتر از یک ساعت پیش بود"
                    except OSError:
                        old = "فقط بسته‌ی همراه برنامه (قدیمی) موجوده"
                    say(f"هیچ لیستی دانلود نشد. از لیست ذخیره‌شده استفاده می‌شه؛ {old} و ممکنه خیلی از کانفیگ‌هاش مرده باشن.")
                add(links, "net")
            except Exception as e:
                say(f"خطا در دانلود لیست‌ها: {type(e).__name__}")
            finally:
                try:
                    add_old()
                finally:
                    T.run_mark("fetch_done", links=fst["n"])
                    fetch_done.set()

        threading.Thread(target=fetcher, daemon=True).start()
        S.update(step=2, pct=8)

        conn = {"busy": False, "t_first": None}

        site_cache = SITE_CACHE

        def pick_first():
            """نامزدهای اتصال اول: فقط سرورهایی که همه‌ی سایت‌های لازم رو واقعاً باز می‌کنن (حالت عادی: یوتیوب، اینستاگرام و تلگرام؛
            «حالت اضطراری»: فقط تلگرام). هیچ‌وقت به کمتر راضی نمی‌شه؛ اگه سروری پیدا نشده خالی برمی‌گرده و جستجو ادامه داره.
            حالت «سرعت»: بین همین‌ها سریع‌ترین."""
            pool = sites_pick(found, site_cache)
            if profile in SPEEDLIKE and len(pool) > 1:
                S.update(step=4, msg=f"در حال سنجش سرعت {'آپلود' if profile == 'upload' else ''} {len(pool)} سرور سالم ...")
                ver = check_many(pool, 1, 5, 3, speed=True, secs=2.0)  # هم‌زمانی کم تا اندازه‌گیری‌ها قابل مقایسه بمونن
                okc = sorted([r for r in ver if r.get("alive") and not danger(r)], key=rk)
                fld = "kbps_up" if profile == "upload" else "kbps"
                kb = {r["raw"]: r.get(fld) for r in okc}
                for c in found:  # سرعت اندازه‌گیری‌شده برای مرحله‌های بعد هم بمونه
                    if kb.get(c["raw"]):
                        c[fld] = kb[c["raw"]]
                if okc:
                    return okc
            return pool[:1]

        def ready_first():
            if profile not in SPEEDLIKE:
                return True
            if conn["t_first"] is None:
                return False
            return (len(found) >= 4 or time.time() - conn["t_first"] >= 8
                    or (fetch_done.is_set() and finished >= pend[0]))

        def maybe_connect(force=False):
            """اتصال رو توی نخ جدا شروع می‌کنه؛ جستجو و به‌روزرسانی صفحه در همین حین ادامه داره."""
            if connected[0] or conn["busy"] or fails[0] >= 4 or STOP.is_set() or not found:
                return
            if not (force or ready_first()):
                return
            now = time.time()
            if not (any(c["raw"] not in site_cache or (not sites_ok(site_cache[c["raw"]]) and now - site_cache[c["raw"]].get("site_t", 0) > 240)
                        for c in list(found)) or any(r.get("alive") and sites_ok(r) for r in list(site_cache.values()))):
                return  # چیز تازه‌ای برای تست نیست و سرور قابل‌قبولی هم نداریم؛ پیام صفحه الکی عوض نشه
            conn["busy"] = True
            S.update(step=4, msg=("در حال انتخاب سریع‌ترین سرور ..." if profile in SPEEDLIKE else smsg("check")))

            def run():
                try:
                    try_connect()
                except Exception:
                    fails[0] += 1
                finally:
                    conn["busy"] = False
                    if not connected[0] and S["stage"] == "running" and not STOP.is_set():
                        S.update(step=2, msg=smsg("none"))
            threading.Thread(target=run, daemon=True).start()

        def try_connect():
            cands = pick_first()
            if not cands:
                return  # هنوز سروری که همه‌ی سایت‌های لازم رو باز کنه پیدا نشده؛ اتصال به سرور بی‌فایده انجام نمی‌شه
            res = connect_ladder(cands, profile, 1)
            if not res:
                fails[0] += 1
                return
            sel, ms, plain = res
            try:
                _, body, _ = cfgscan.fetch(SOCKS, cfgscan.IP_URL, 10)
                ip = body.decode("ascii", "ignore").strip()[:45]
            except Exception:
                ip = ""
            if STOP.is_set():
                return
            if sysproxy:
                set_proxy(HTTP)
            real = direct_ip()
            leak = "unknown" if not (real and ip) else ("leak" if ip == real else "ok")
            okset = {k for k, r in site_cache.items() if sites_ok(r)}
            POOL.update(active=sel, standby=sorted([c for c in found if c["raw"] != sel[0]["raw"] and (c["raw"] in okset or c["raw"] not in site_cache)],
                                                   key=lambda c: c["raw"] not in okset)[:40],
                        switches=0, real_ip=real, sites=sel[0].get("sites"))
            for c in POOL["standby"]:
                if c["raw"] in okset:
                    c["sites"] = site_cache[c["raw"]]["sites"]
            connected[0], t_first[0] = True, time.time()
            T.run_mark("connected", tested=DIAG.get("tested"), alive=len(found))
            T.evt("connected", f"وصل شد: {sel[0]['proto']}/{sel[0]['network']}/{sel[0]['security']} پینگ {ms}ms")
            save_good(sel)
            S.update(stage="connected", pct=100, msg="وصل شدی ✓", connected=dict(
                ip=ip, ms=ms, n=len(sel), warn=describe(sel[0])["warn"], leak=leak, real_ip=real,
                best=f"{sel[0]['proto']} / {sel[0]['network']} / {sel[0]['security']} / پورت {sel[0]['port']}",
                system=bool(sysproxy and os.name == "nt")),
                note="در حال یافتن سرورهای بیشتر برای جابه‌جایی خودکار ..." if failover_on else "")
            MODE[0] = mode  # نظارت از همین لحظه فعاله؛ منتظر تموم‌شدن جستجو نمی‌مونه
            FAILOVER.set() if failover_on else FAILOVER.clear()
            threading.Thread(target=supervisor, args=(GEN[0], profile, sysproxy, mode), daemon=True).start()
            threading.Thread(target=sites_guard, args=(GEN[0], profile, found), daemon=True).start()
            threading.Thread(target=standby_sites, args=(GEN[0],), daemon=True).start()
            threading.Thread(target=sites_watch, args=(GEN[0], profile, found), daemon=True).start()
            threading.Thread(target=bench_loop, args=(GEN[0],), daemon=True).start()
            threading.Thread(target=call_monitor, args=(GEN[0],), daemon=True).start()
            if profile == "auto" and APIPORT[0]:
                threading.Thread(target=auto_watch, args=(GEN[0], profile, sysproxy), daemon=True).start()
            if CALL[0]:  # حالت تماس از قبل روشن بوده؛ بعد از وصل‌شدن خودش دنبال سرور مناسب تماس می‌گرده
                threading.Thread(target=_call_after_connect, args=(GEN[0], profile), daemon=True).start()

        finished, why = 0, ""
        while not STOP.is_set():
            try:
                c = q.get(timeout=0.4)
            except queue.Empty:
                maybe_connect()
                if fetch_done.is_set() and finished >= pend[0]:
                    why = f"همه‌ی {finished} کانفیگ تست شدن."
                    break
                if time.time() - t0 > hard_cap:
                    why = (f"زمان جستجو تموم شد ({int(hard_cap // 60)} دقیقه)؛ {finished} از {pend[0]} کانفیگ تست شد. "
                           "برای تست بیشتر، سرعت اسکن رو بالاتر ببر یا حالت «کامل» رو بزن.")
                    break
                continue
            finished += 1
            S["blocked"] = blk[0]
            if c.get("alive") and not danger(c):
                found.append(c)
                c.setdefault("verified_at", time.time())
                if conn["t_first"] is None:
                    conn["t_first"] = time.time()
                if connected[0]:  # از همون لحظه جایگزین آماده برای جابه‌جایی داشته باشیم
                    have = {x["raw"] for x in POOL["standby"] + POOL["active"]}
                    if c["raw"] not in have and len(POOL["standby"]) < 40:
                        POOL["standby"].append(c)
                else:
                    maybe_connect()
            if not connected[0] and not conn["busy"]:
                S["pct"] = min(70, 8 + int(62 * finished / max(1, pend[0])))
                if S["stage"] == "running" and S["step"] == 2:
                    S["msg"] = smsg("none" if found else "") + ("" if fetch_done.is_set() else " | منابع در حال دانلود ...")
            elif S["stage"] == "connected" and failover_on:
                S["note"] = f"در حال یافتن سرورهای بیشتر ... ({len(found)} سرور سالم تا الان)"
            if len(found) >= target:
                why = f"به تعداد کافی سرور سالم پیدا شد ({len(found)}؛ تست {finished} از {pend[0]})."
                break
            if t_first[0] and time.time() - t_first[0] > up_cap:
                why = f"جستجوی پس‌زمینه بعد از {up_cap} ثانیه از اتصال تموم شد ({len(found)} سرور سالم؛ تست {finished} از {pend[0]})."
                break
        ended[0] = True
        old_timer.cancel()
        ex.shutdown(wait=False, cancel_futures=True)
        if found and not connected[0] and not STOP.is_set():
            maybe_connect(force=True)  # جستجو تموم شد ولی هنوز وصل نشدیم
        while conn["busy"] and not STOP.is_set():
            time.sleep(0.2)
        T.run_end(why or ("cancel" if STOP.is_set() else ""), tested=finished, alive=len(found), pend=pend[0], connected=bool(connected[0]))
        if why and not STOP.is_set():
            say("پایان جستجو: " + why)
        if STOP.is_set():
            if S["stage"] == "running":
                raise Cancel
            return
        tested = [c for c in cands if c.get("tested")]
        reach_ok = sum(1 for c in tested if c.get("reachable"))
        try:  # آمار روش‌ها برای فایل گزارش (کانفیگ‌های سالمِ ذخیره‌شده‌ی قبلی سوگیری دارن و حساب نمی‌شن)
            use = [c for c in tested if c.get("src") != "good"]
            extra = dict(blocked=blk[0], unsupported=skip["unsupported"], insecure=skip["insecure"])
            report.add_run(RUN, use, **extra)
            report.add_run(CUM, use, **extra)
            report.save(STATS_FILE, CUM)
        except Exception:
            pass
        LEARN["runs"] += 1
        _learn_state["dirty"] = True
        learn_save(True)
        if _ev and not auto:  # ثبت نتیجه برای تنظیم خودکار تعداد تست هم‌زمان
            try:
                real = [c for c in tested if c.get("src") != "good"]
                _ev.tune_note(len(real), sum(1 for c in real if c.get("alive")), (t_first[0] - t0) if t_first[0] else None)
                threading.Thread(target=_ev.enforce, daemon=True).start()
            except Exception:
                pass
        if not clock[0]:
            _commit_bad(pend)
        bad_save(True)
        save_localblock()
        prune_sources()
        for c in found:
            for s in db["sources"]:
                if c["raw"] in origin and s["url"] == origin[c["raw"]]:
                    s["alive"] += 1
        fresh = load_db()  # منبعی که وسط جستجو اضافه یا حذف شده از بین نره
        idx = {x["url"]: x for x in fresh["sources"]}
        for x in db["sources"]:
            if x["url"] in idx:
                idx[x["url"]].update(got=x.get("got", 0), alive=x.get("alive", 0))
        save_db(fresh)
        if (not connected[0] and not STOP.is_set() and cycle < (30 if found else 8)  # سرور سالم هست ولی هیچ‌کدوم شرط سایت‌ها رو نداره: بی‌وقفه با منابع تازه ادامه بده
                and not (P["only_encrypted"] and fst["n"] and not tested)):
            nxt = 2 if level >= 3 else level + 1  # هیچ‌وقت تسلیم نمی‌شه: مرحله‌ی بعد، بعد از کمی صبر دوباره از مرحله‌ی ۲
            POOL["tiers"] = site_tiers(site_cache)
            S.update(stage="running", step=2, pct=8,
                     msg=(f"سرور سالم هست ولی هیچ‌کدوم {_want()} رو باز نکرد؛ دنبال سرورهای بیشتر می‌گردم (مرحله {nxt}) ..." if found
                          else f"وصل نشد؛ تلاش با روش‌های قوی‌تر (مرحله {nxt}) ..."))
            if level >= 3:
                for _ in range(30):
                    if STOP.is_set():
                        break
                    time.sleep(1)
            if not STOP.is_set():
                return pipeline(profile, quick, sysproxy, failover_on, auto, nxt, cycle + 1)
            raise Cancel
        if not connected[0]:
            if not tested and P["only_encrypted"] and fetch_done.is_set() and fst["n"]:
                raise RuntimeError("در حالت «امنیت» هیچ کانفیگ رمزنگاری‌شده‌ی بدون هشدار پیدا نشد. حالت «پایداری» یا «متعادل» رو امتحان کن.")
            if not tested:
                raise RuntimeError("نه به منابع GitHub (و آینه‌هاشون) دسترسی داشتیم و نه کانفیگ ذخیره‌شده‌ای بود. "
                                   "از بخش «منابع» ← «افزودن دستی» چند کانفیگ از دوستات یا کانال‌ها بذار؛ همون‌ها تست می‌شن.")
            if not found:
                hint = ("هیچ سروری از شبکه‌ی تو در دسترس نبود؛ اینترنت یا فیلتر خیلی شدیده." if reach_ok == 0 else
                        "سرورها به اتصال جواب دادن ولی هیچ‌کدوم ترافیک واقعی رد نکردن؛ معمولاً یعنی فیلتر عمیق یا محدودیت آپلود. "
                        "حالت «کامل» یا منابع بیشتر رو امتحان کن.")
                src = "" if fst["n"] else " (دانلود منابع هم موفق نبود)"
                raise RuntimeError(f"از {len(tested)} کانفیگ تست‌شده، {reach_ok} تا به اتصال جواب دادن و {len(found)} تا سالم بودن.{src} {hint}")
            tr = site_tiers(site_cache)
            POOL["tiers"] = tr
            if tr["tested"]:
                if TGONLY[0]:
                    raise RuntimeError(f"{len(found)} سرور سالم پیدا شد ولی هیچ‌کدوم تلگرام رو باز نکرد. چند ساعت بعد دوباره اسکن کن.")
                raise RuntimeError(f"{len(found)} سرور سالم پیدا شد ولی هیچ‌کدوم یوتیوب، اینستاگرام و تلگرام رو با هم باز نکرد "
                                   f"({tr['ytig']} تا فقط یوتیوب و اینستاگرام، {tr['tg']} تا فقط تلگرام). چند ساعت بعد دوباره اسکن کن"
                                   + (" یا «حالت اضطراری: فقط تلگرام» رو روشن کن." if tr["tg"] else "."))
            raise RuntimeError(f"{len(found)} سرور سالم پیدا شد ولی اتصال نهایی برقرار نشد. دوباره امتحان کن.")
        # اولین سرورِ وصل‌شده فقط «موقتی»ه؛ همه‌ی سرورهای سالم با تست آروم و چندنمونه‌ای دوباره و منصفانه سنجیده می‌شن
        if profile in SPEEDLIKE:  # سرور با سرعتِ اندازه‌گیری‌شده‌ی بیشتر اول؛ بعد ناشناخته‌ها با پینگ
            ranked = sorted(found, key=lambda c: (0 if spd(c, profile) else 1, -(spd(c, profile) or 0), ping_key(c)))
        else:
            ranked = sorted(found, key=ping_key)
        cur = list(POOL["active"])
        if S["stage"] == "connected" and cur and not STOP.is_set():
            SWITCH.acquire()
            held[0] = True
            S["note"] = "در حال بررسی دقیق سرورها ..."
            others = [c for c in ranked if c["raw"] != cur[0]["raw"]]
            nfix = 12 if profile in SPEEDLIKE else 8
            def known_bad(c):  # همین چند دقیقه‌ی پیش تست سایت شده و رد شده؛ دوباره وقت صرفش نمی‌کنیم
                r = site_cache.get(c["raw"])
                return bool(r and time.time() - r.get("site_t", 0) < SITE_FRESH and not sites_ok(r))
            others = [c for c in others if not known_bad(c)]
            top = others[:nfix] + random.sample(others[nfix:], min(4, len(others[nfix:]))) + [cur[0]]
            # sites=True: قبلاً این مرحله فقط تأخیر/سرعت می‌سنجید و می‌تونست از سروری که یوتیوب رو باز می‌کرد به سرور سریع‌ترِ بی‌یوتیوب بپره
            if profile in SPEEDLIKE:  # هم‌زمانی کم و نمونه‌ی بلندتر: مقایسه‌ی منصفانه‌ی سرعت
                ver = check_many(top, ROUNDS.get(profile, 3), 5, 2, speed=True, secs=3.0, sites=True)
            else:
                ver = check_many(top, ROUNDS.get(profile, 3), 5, 4, speed=True, secs=2.0, sites=True)
            if STOP.is_set():
                return
            okc = sorted([r for r in ver if solid(r, need_ok()) and sites_ok(r)], key=rk)
            curv = next((r for r in ver if r["raw"] == cur[0]["raw"]), None)
            cur_ok = bool(curv and solid(curv, need_ok()) and sites_ok(curv))
            if mode == "fast" and len(okc) > 1:
                res = connect_ladder(okc, profile, POOL_SIZE)
                if res:
                    set_active(res[0], res[1])
                    POOL["standby"] = [r for r in okc if r not in res[0]] + ranked[12:40]
                else:
                    start_xray(cur, profile, True)
                    POOL["standby"] = okc
            else:
                best = okc[0] if okc else None
                if curv and solid(curv, need_ok()):
                    POOL["active"] = [curv]  # همون سرور فعلی، با اندازه‌گیری‌های دقیق‌تر
                if best and best["raw"] != cur[0]["raw"] and (not cur_ok or (rk(best) < rk(curv) and cost(best) < 0.75 * cost(curv))):
                    sel = start_xray([best], profile)
                    ms = probe_retry(3, 4)
                    if ms:
                        set_active(sel, ms)
                    else:
                        start_xray(cur, profile, True)  # بازگشت به سرور قبلی
                POOL["standby"] = [r for r in okc if r["raw"] != POOL["active"][0]["raw"]] + ranked[12:40]
            now = time.time()
            for c in POOL["standby"]:
                c.setdefault("verified_at", now)
            if held[0]:
                held[0] = False
                SWITCH.release()
        save_good(POOL["active"] + POOL["standby"])
        MODE[0] = mode
        FAILOVER.set() if failover_on else FAILOVER.clear()
        S["note"] = (f"{len(POOL['active'])} سرور فعال و {len(POOL['standby'])} جایگزین آماده‌ست." if failover_on else "")
        POOL["backlog"] = [c for c in cands if not c.get("tested")]
        threading.Thread(target=refill, args=(GEN[0], profile, seen), daemon=True).start()
        threading.Thread(target=channels_retry, args=(GEN[0], profile, seen), daemon=True).start()
    except Cancel:
        disconnect(silent=True)
        S.update(stage="idle", step=0, pct=0, msg="لغو شد", note="")
    except Exception as e:
        disconnect(silent=True)
        S.update(stage="error", msg=str(e))
        T.err("pipeline", e)
        T.run_end("error: " + str(e)[:100])
        T.incident("pipeline_error", **_inc_state())
    finally:
        RUNNING[0] -= 1
        if held[0]:
            held[0] = False
            SWITCH.release()


# ------------------------------------------------------------ سرور محلی
def state():
    d = dict(S)
    d["log"] = S["log"][-25:]
    d["sources"] = load_db()["sources"]
    d["win"] = os.name == "nt"
    d["android"], d["vpn"] = ANDROID, VPN[0]
    d["res"] = cfgres.GOV.summary() if (cfgres is not None and ANDROID) else ""
    d["sensors"] = (dict(blind=cfgres.GOV.temp_blind(), mode=cfgres.GOV.notemp)
                    if (cfgres is not None and ANDROID and cfgres.GOV.active()) else None)
    d["res_info"] = cfgres.GOV.report_fa() if (cfgres is not None and ANDROID) else ""
    d["sites"], d["fetch"] = POOL.get("sites"), FETCHINFO
    d["cdp"] = CDP[0]
    d["methods"] = report.table(RUN["methods"], 8)
    d["rsum"] = {k: RUN[k] for k in ("tested", "reach", "alive", "blocked")}
    d["rsum"]["runs_total"] = CUM["runs"]
    d["servers"] = [dict(describe(c), role="active") for c in POOL["active"]] + \
                   [dict(describe(c), role="standby") for c in standby_ok()[:12]]
    d["switches"], d["failover"] = POOL["switches"], FAILOVER.is_set()
    d["mode"] = MODE[0]
    d["ports"] = [SOCKS, HTTP]
    d["profile"] = CUR[0]
    d["settings"] = load_settings()
    d["tgonly"], d["tiers"], d["learn"] = TGONLY[0], POOL.get("tiers"), learn_summary()
    d["call"] = call_state()
    d["net"], d["diag"], d["link"], d["evolve"] = net_view(), dict(DIAG, skip=dict(DIAG.get("skip") or {})), S.get("link", ""), bool(_ev)
    d["bench"] = len(POOL.get("bench") or [])
    d["data"] = data_view()
    d["disc"] = dict(DISC, last=LEARN["disc_t"])
    d["autosrc"] = [dict(url=x["url"], got=x.get("got", 0), on=bool(x.get("on")), off=bool(x.get("auto_off")),
                         tested=int((source_v(x["url"]) or [0])[0]), passed=int((source_v(x["url"]) or [0, 0, 0, 0])[3]))
                    for x in d["sources"] if x.get("kind") == "auto"]
    return d


def quit_app(uninstall=False):
    QUITTING[0] = True
    STOP.set()
    t0 = time.time()
    while S["stage"] == "running" and time.time() - t0 < 6:
        time.sleep(0.2)
    shutdown()
    if uninstall:  # اگه حذف نیمه‌کاره موند، دفعه‌ی بعد لانچر فایل‌ها رو دوباره کامل باز می‌کنه
        try:
            (ROOT / "version.txt").unlink()
        except OSError:
            pass
    if uninstall and os.name == "nt" and re.fullmatch(r"[\w\s:\\./()-]+", str(ROOT)):  # فقط مسیر امن؛ بدون shell
        subprocess.Popen(f'cmd /c ping 127.0.0.1 -n 6 >nul & rmdir /s /q "{ROOT}"',
                         creationflags=0x00000008 | 0x08000000)
    os._exit(0)


def shutdown():
    cfgdata.save(True)
    learn_save(True)  # یادگیری و حافظه‌ی بد با بستن برنامه از دست نمی‌رن
    bad_save(True)
    callmem_save(True)
    disconnect(silent=True)
    try:
        (DATA / "run.json").unlink()
    except OSError:
        pass
    if WIN and os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(WIN.pid), "/T", "/F"], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


MAX_BODY = 8_000_000  # بزرگ‌ترین بدنه‌ی POST (افزودن دستی تا ۲ میلیون کاراکتر فارسی/یونیکد قبول می‌کنه)


def _cfg_row(c):
    """فقط ویژگی‌های بی‌خطر یک کانفیگ؛ آدرس، شناسه و نام هرگز."""
    return {k: c.get(k) for k in ("proto", "network", "security", "port", "ms", "kbps", "kbps_up", "src", "alive", "reachable", "flow", "fp", "alpn", "scy", "frag", "mode", "insecure") if k in c}


def _res_snapshot():
    """وضعیت کنترل مصرف منابع گوشی (ضریب، دلیل کاهش، دما و رم) برای گزارش؛ فقط عددها، بدون هیچ داده‌ی شخصی."""
    try:
        if cfgres is None or not ANDROID:
            return None
        g = cfgres.GOV
        env = {k: v for k, v in dict(g.env).items() if isinstance(v, (int, float, bool))}
        return {"factor": round(g.s, 2), "why": str(g.why)[:200], "mem_live": g.mem_live, "proc_mb": g.proc_mb, "sensors": g.report_fa()[:300],
                "env_age_s": round(time.time() - g.t_env, 1) if g.t_env else None, "env": env,
                "log": [[round(a, 1), round(b, 2), str(c)[:80]] for a, b, c in list(g.log)[-30:]]}
    except Exception:
        return None


SERIES = deque(maxlen=180)  # هر ۱۰ ثانیه یک نمونه‌ی عددی؛ ۳۰ دقیقه‌ی اخیر
HTTPS = {"last_state_t": 0.0}


def _safe_fp():
    try:
        return (netprobe.net_fp() if netprobe else "") or ""
    except Exception:
        return ""


def _thread_census():
    out = {}
    for t in threading.enumerate():
        tg = getattr(t, "_target", None)
        n = getattr(tg, "__name__", None) or t.name.split("-")[0]
        out[n] = out.get(n, 0) + 1
    return out


def series_loop():
    """نمونه‌برداری آرام از شاخص‌های اصلی؛ بعداً می‌شه دید «کِی» چی عوض شد (نه فقط حالا چیه)."""
    while True:
        time.sleep(10)
        try:
            pr = S.get("prog") or {}
            c = S.get("connected") or {}
            SERIES.append({"t": int(time.time() - T.T0), "stage": S.get("stage"), "pct": S.get("pct"), "tested": pr.get("tested"), "alive": pr.get("alive"),
                           "rate": pr.get("rate"), "ms": c.get("ms") if isinstance(c, dict) else None, "link": S.get("link", ""),
                           "standby": len(POOL.get("standby") or []), "active": len(POOL.get("active") or []),
                           "act": (S.get("act") or {}).get("act"), "mb": cfgdata.snapshot()["today"].get("total", 0) // 1000000,
                           "saver": data_saver(), "mob": net_is_mobile(), "netchg": NETCHG["n"], "lg": LOAD.snapshot().get("f"),
                           "threads": threading.active_count()})
        except Exception as e:
            T.err("series_loop", e)


def evolve_extra():
    """بخش‌های تازه‌ی گزارش: مصرف اینترنت، تغییر شبکه، نخ‌ها، همگام‌سازی صفحه، سری زمانی، تنظیمات واقعیِ در حال اجرا و خلاصه‌ی بالای گزارش."""
    t = cfgdata.snapshot()
    perf = T.snapshot().get("perf", {})
    eff = {"profile": CUR[0], "mode": MODE[0], "eff_mode": eff_mode(MODE[0]), "speed": SPEED[0], "eff_speed": eff_speed(), "call": CALL[0], "tgonly": TGONLY[0],
           "direct": DIRECT[0], "sysproxy_want": VPN_WANT[0], "failover": FAILOVER.is_set(), "data_budget_mb": data_budget_mb(), "data_saver": data_saver(),
           "mobile": net_is_mobile(), "api_port": bool(APIPORT[0])}
    dv = data_view()
    summary = {"stage": S.get("stage"), "msg": (S.get("msg") or "")[:160], "profile": CUR[0], "mode": MODE[0], "link": S.get("link", ""),
               "data_today_mb": dv["mb"], "data_budget_mb": dv["budget"], "mobile": dv["mobile"], "saver": dv["saver"],
               "net_changes": NETCHG["n"], "switches": POOL.get("switches", 0), "standby": len(POOL.get("standby") or []),
               "act": (S.get("act") or {}).get("act"), "app_started_s_ago": int(time.time() - T.T0)}
    return {"summary": summary,
            "data": dict(t, view=dv, per_test_overhead_bytes=cfgdata.OVERHEAD_TEST,
                         note="بایت‌ها تخمینی‌ان (سربار TLS/TCP ثابت فرض شده)؛ سهم هر دسته و مرتبه‌ی بزرگی درسته"),
            "net_changes": {"n": NETCHG["n"], "last_s_ago": int(time.time() - NETCHG["t"]) if NETCHG["t"] else None, "log": list(NETCHG["log"]),
                            "now": FA_NET.get(_safe_fp().split("#")[0].split(":")[0], "?")},
            "search_now": {"running": RUNNING[0], "pipeline_alive": bool(PIPE and PIPE.is_alive()), "prog": S.get("prog"), "stage": S.get("stage"),
                           "step": S.get("step"), "pct": S.get("pct")},
            "threads": _thread_census(),
            "ui_sync": {k: perf.get(k) for k in perf if k.startswith("http_") or k == "ui_state_gap"},
            "effective": eff,
            "series": list(SERIES)}


def evolve_ctx():
    """آمار کامل برنامه برای گزارش تکامل. آدرس منبع‌های عمومی گیت‌هاب فقط به شکل «مالک/ریپو/فایل» میاد؛
    هیچ لینک شخصی، کانال، آدرس سرور یا توکنی نمیاد (و بعدش همه‌چیز دوباره فیلتر می‌شه)."""
    srcs = []
    for x in load_db()["sources"]:
        u = x.get("url", "")
        pu = urllib.parse.urlsplit(u)
        if pu.scheme == "https" and pu.hostname in ("raw.githubusercontent.com", "github.com") and not pu.query:
            v = source_v(u)
            srcs.append({"src": pu.path.strip("/")[:90], "kind": x.get("kind", "default"), "on": bool(x.get("on")),
                         "got": x.get("got", 0), "alive": x.get("alive", 0), "yield": round(source_yield(u), 4),
                         "auto_off": bool(x.get("auto_off")), "revived": bool(x.get("revived")),
                         "age_d": round((time.time() - x.get("added", time.time())) / 86400, 1) if x.get("added") else None,
                         "learn": [round(n, 1) for n in v] if v else None})
    ls = learn_summary()
    if ls:
        ls = dict(ls, source=[urllib.parse.urlsplit(u).path.strip("/")[:90] for u in ls.get("source", [])])
    st = load_settings()
    now = time.time()
    f = LEARN["f"]
    tables = {}
    for pre, name in (("p:", "proto"), ("n:", "network"), ("o:", "port"), ("s:", "security"), ("t:", "tls")):
        rows = sorted(((k[len(pre):], [round(x, 1) for x in v]) for k, v in f.items() if k.startswith(pre)), key=lambda r: -r[1][0])[:40]
        if rows:
            tables[name] = dict(rows)
    other = sum(1 for k in f if not k[:2] in ("p:", "n:", "o:", "s:", "t:"))
    bad_kinds = {}
    for v in BAD["h"].values():
        k = v[2] if len(v) > 2 else "?"
        bad_kinds[k] = bad_kinds.get(k, 0) + 1
    nets = {k: {"keys": len(v.get("k", {})), "last_h_ago": round((now - v.get("last", 0)) / 3600, 1)} for k, v in list(LEARN["a"].items())[:20]}
    try:
        sp = speed_params()
    except Exception:
        sp = {}
    pool = {"switches": POOL.get("switches", 0), "active": [_cfg_row(c) for c in POOL.get("active", [])[:10] if isinstance(c, dict)],
            "standby": [_cfg_row(c) for c in POOL.get("standby", [])[:30] if isinstance(c, dict)],
            "standby_n": len(POOL.get("standby", [])), "backlog_n": len(POOL.get("backlog", []))}
    _trace = T.snapshot()
    try:
        import cfgtrace as _ct
        _hints = _ct.hints(_trace, {"loadguard": LOAD.snapshot()})
    except Exception:
        _hints = []
    return {**evolve_extra(),
            "settings": {k: st.get(k) for k in ("profile", "mode", "speed", "quick", "sysproxy", "tgonly", "autosrc", "call", "direct", "data_mb")},
            "resource": _res_snapshot(),
            "loadguard": LOAD.snapshot(),  # ضریب ترمز CPU، دیرکرد پردازه، سهم CPU (برای تنظیم سقف‌ها از روی گزارش واقعی)
            "auto": {"profile": CUR[0], "api": bool(APIPORT[0]), "diag": {k: v for k, v in AUTO["diag"].items() if not k.startswith("_")}, "act": S.get("act"), "cool_in_s": max(0, int(AUTO["cool"] - time.time())),
                     "decisions": list(AUTO["log"])},  # فوق هوشمند: فعالیت تشخیص‌داده‌شده و تصمیم‌های اخیر (بدون هیچ آدرس/میزبانی)
            "trace": _trace, "hints": _hints,  # خط زمانی رویدادها، خطاهای بلعیده‌شده، زمان‌سنجی، زمان‌بندی جستجوها، لحظه‌های مشکل + خلاصه‌ی خودکار
            "speed_now": SPEED[0], "speed_effective": sp, "speed_table": SPEEDS, "profile_now": CUR[0],
            "flags": {"tgonly": TGONLY[0], "call": CALL[0], "vpn": VPN[0], "vpn_want": VPN_WANT[0], "background": BG[0], "android": bool(ANDROID),
                      "xray_running": bool(XRAY_PROC), "pipeline_alive": bool(PIPE and PIPE.is_alive()), "ports": {"socks": SOCKS, "http": HTTP}},
            "stage": {"stage": S["stage"], "step": S["step"], "pct": S["pct"], "msg": S["msg"], "note": S["note"], "warn": S["warn"],
                      "blocked": S["blocked"], "connected": bool(S.get("connected"))},
            "stats": CUM, "last_run": RUN, "learn": ls, "learn_tables": tables, "learn_other_keys": other,
            "learn_state": {"runs": LEARN["runs"], "keys": len(f), "sec_keys": len(LEARN["s"]), "nets": nets, "disc_ok": LEARN["disc_ok"],
                            "disc_h_ago": round((now - LEARN["disc_t"]) / 3600, 1) if LEARN["disc_t"] else None},
            "learn_constants": {"prior": LEARN_PRIOR, "max_keys": LEARN_MAX_KEYS, "auto_max": AUTO_MAX, "bad_hours": BAD_HOURS,
                                "bad_explore": BAD_EXPLORE, "bench_steps": BENCH_STEPS},
            "quarantine": {"total": len(BAD["h"]), "active": sum(1 for v in BAD["h"].values() if v[0] > now), "by_kind": bad_kinds},
            "discovery": {k: DISC.get(k) for k in ("t", "msg", "added", "running")},
            "netprobe": NETP.get("net"), "pool": pool, "sources": srcs[:60],
            "blocklist_entries": (lambda b: {"ips": len(b.ips), "ranges": len(b.starts)} if b is not None and hasattr(b, "ips") else None)(getattr(cfgscan, "BLOCK", None)),
            "av": {"local_block_saved": len(cfgscan.LOCAL_BLOCK), "pace_factor": AVF[0], "os": os.name,
                   "run_diag": DIAG.get("local_block", 0)},  # آنتی‌ویروس/فایروالِ دستگاه چند آدرس رو بسته (فقط شمارش؛ آدرس‌ها وارد گزارش نمی‌شن)
            "recent_log": S["log"][-60:]}


def evolve_post(p, j):
    try:
        if p in ("/api/evolve/inspect", "/api/evolve/apply"):
            data = base64.b64decode(str(j.get("b64", "")), validate=True)
            if p.endswith("inspect"):
                return _ev.inspect_patch(data)
            if ANDROID:  # کد برنامه داخل APK فقط‌خوانده؛ توی گوشی فقط «گزارش» کار می‌کنه و وصله با آپلود فایل‌ها توی گیت‌هاب و ساخت APK تازه نصب می‌شه
                return {"ok": False, "errors": ["توی نسخه‌ی موبایل نصب وصله ممکن نیست؛ فایل‌های جدید رو توی گیت‌هاب آپلود کن و APK تازه بساز."]}
            if S["stage"] == "running":
                return {"ok": False, "errors": ["الان جستجو در حاله؛ بعد از پایانش نصب کن."]}
            if load_settings().get("evolve_ok") is not True:  # پیش‌فرض خاموشه: نصب وصله = اجرای کد تازه؛ فقط وقتی خودت روشنش کنی
                return {"ok": False, "errors": ["نصب وصله خاموشه. اول توی همین تب کلید «اجازه‌ی نصب وصله» رو روشن کن."]}
            return {"ok": _ev.apply_patch(data)}
        if p == "/api/evolve/rollback":
            ok, msg = _ev.rollback("original" if j.get("mode") == "original" else "last")
            return {"ok": ok, "msg": msg}
        if p == "/api/evolve/cap":
            return {"ok": True, "freed": _ev.set_cap(int(j.get("mb", 20)))}
        if p == "/api/evolve/autotune":
            _ev.set_autotune(bool(j.get("on")))
            return {"ok": True}
    except Exception:
        return {"ok": False, "errors": ["درخواست نامعتبر بود."]}
    return {"ok": False, "errors": ["نامعلوم"]}


def start_session(j):
    """جستجو و اتصال با تنظیمات j (دکمه‌ی «اتصال» و حالت تماس هر دو از همین‌جا شروع می‌کنن)."""
    global PIPE
    DIRECT[0] = j.get("direct") if _in(j.get("direct"), cfgforge.COUNTRY_DIRECT) else ""
    VPN_WANT[0] = bool(j.get("sysproxy", True))
    TGONLY[0] = bool(j.get("tgonly", False))
    SITE_CACHE.clear()
    POOL["tiers"] = None
    if _in(j.get("speed"), SPEEDS):
        SPEED[0] = j["speed"]
    with START_LOCK:  # دو «شروع» پشت‌سرهم دو اجرای هم‌زمان نسازن
        if PIPE and PIPE.is_alive():
            STOP.set()
            PIPE.join(20)
        if PIPE and PIPE.is_alive():  # اجرای قبلی هنوز در حال بسته‌شدنه؛ اجرای تازه روی دست اون شروع نمی‌شه
            S["msg"] = "اجرای قبلی هنوز در حال توقفه؛ چند ثانیه بعد دوباره شروع کن."
            return {"ok": False, "error": "busy"}
    prof = j.get("profile") if _in(j.get("profile"), cfgforge.PROFILES) else "auto"
    PIPE = threading.Thread(target=pipeline, args=(prof, bool(j.get("quick", True)),
                                                   bool(j.get("sysproxy", True)),
                                                   j.get("mode") if _in(j.get("mode"), ("stable", "fast", "off")) else "stable"),
                            daemon=True)
    PIPE.start()
    return {"ok": True}


class H(http.server.BaseHTTPRequestHandler):
    timeout = 10  # اتصال نیمه‌باز (slowloris) بعد از ۱۰ ثانیه بسته می‌شه

    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="application/json; charset=utf-8", headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def auth(self, q):
        if self.headers.get("Host", "") not in (f"127.0.0.1:{PORT}", f"localhost:{PORT}"):
            return False
        org = self.headers.get("Origin")  # صفحه‌ی وب دیگه (CSRF) حق درخواست نداره، حتی اگه توکن رو بدونه
        if org is not None and org not in (f"http://127.0.0.1:{PORT}", f"http://localhost:{PORT}"):
            return False
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            return False
        t = q.get("t", [""])[0] or self.headers.get("X-T", "")
        return secrets.compare_digest(t.encode("utf-8", "replace"), TOKEN.encode())  # بایت؛ با رشته‌ی غیر ASCII خود compare_digest خطا می‌داد

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self.auth(q):
            return self.reply(403, b"", "text/plain")
        if u.path == "/":
            nonce = secrets.token_urlsafe(12)  # فقط اسکریپت خودِ برنامه اجرا بشه؛ حتی اگه یه روز محتوای تزریقی به صفحه برسه نمی‌تونه کد اجرا کنه یا چیزی بیرون بفرسته
            html = ((HERE / "ui.html").read_text(encoding="utf-8").replace("__T__", TOKEN)
                    .replace("<script>", f'<script nonce="{nonce}">', 1))
            if not _ev:  # تکامل (نصب وصله) فقط وقتی ماژولش هست؛ اندروید فایل‌های برنامه رو فقط‌خواندنی داره
                html = html.replace('id="sec-evo"', 'id="sec-evo" data-off="1"')
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; img-src 'self' data:; "
                   "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
            return self.reply(200, html.encode(), "text/html; charset=utf-8", {"Content-Security-Policy": csp})
        if u.path == "/api/state":
            # since=<هش>: تا وقتی وضعیت عوض نشده (حداکثر ۱۲ ثانیه) صبر می‌کنه و به‌محض تغییر جواب می‌ده؛ صفحه تقریباً لحظه‌ای هماهنگ می‌شه
            since, t0 = (q.get("since") or [""])[0][:16], time.time()
            while True:
                S["beat"] = time.time()
                d = state()
                h = hashlib.md5(json.dumps({k: v for k, v in d.items() if k != "beat"}, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:12]
                if not since or h != since or time.time() - t0 > 12 or QUITTING[0]:
                    d["_h"] = h
                    return self.reply(200, d)
                time.sleep(0.2)
        if u.path == "/api/evolve" and _ev:
            return self.reply(200, _ev.status())
        if u.path == "/api/evolve/report" and _ev:  # فایل گزارش مهرشده برای Claude
            plain = bool(q.get("plain"))
            rid, text = _ev.make_report(evolve_ctx(), plain=plain)
            try:
                _ev.save_report_file(text)
            except OSError:
                pass
            return self.reply(200, text.encode("utf-8"), "text/plain; charset=utf-8",
                              {"Content-Disposition": 'attachment; filename="ConfigTool-report-%s.%s"' % (time.strftime("%Y%m%d-%H%M"), "txt" if plain else "ctreport")})
        if u.path == "/report":
            hdr = {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; "
                                              "form-action 'none'; frame-ancestors 'none'"}
            if q.get("dl"):
                hdr["Content-Disposition"] = 'attachment; filename="network-report-%s.html"' % time.strftime("%Y%m%d-%H%M")
            return self.reply(200, report.render(RUN, CUM).encode("utf-8"), "text/html; charset=utf-8", hdr)
        self.reply(404, b"", "text/plain")

    def do_POST(self):
        u = urllib.parse.urlsplit(self.path)
        if not self.auth(urllib.parse.parse_qs(u.query)):
            return self.reply(403, b"", "text/plain")
        try:
            n = int(self.headers.get("Content-Length", 0))
            if n < 0:
                raise ValueError("negative length")
            if n > MAX_BODY:  # قبلاً بدنه بی‌صدا بریده می‌شد و JSON خراب می‌شد؛ حالا صریح رد می‌شه
                return self.reply(413, {"error": "big"})
            j = json.loads(self.rfile.read(n) or b"{}")
            if not isinstance(j, dict):
                raise ValueError("not an object")
        except Exception:
            return self.reply(400, {"error": "bad"})
        p = u.path
        if p.startswith("/api/evolve") and _ev:
            return self.reply(200, evolve_post(p, j))
        if p == "/api/call":
            on = bool(j.get("on"))
            set_call(on)
            save_settings({"call": on})
            if on and S["stage"] == "connected":
                threading.Thread(target=call_prepare, args=(GEN[0], CUR[0], bool(j.get("switch", True))), daemon=True).start()
            elif on and S["stage"] != "running":  # وصل نیستی: حالت تماس خودش با تنظیمات ذخیره‌شده اتصال رو شروع می‌کنه
                sj = {k: v for k, v in load_settings().items() if k in ("profile", "mode", "speed", "quick", "sysproxy", "tgonly", "direct")}
                threading.Thread(target=lambda: start_session(sj), daemon=True).start()
            return self.reply(200, {"ok": True, "call": call_state()})
        if p == "/api/call/test":
            if S["stage"] != "connected":
                return self.reply(200, {"ok": False, "error": "not_connected"})
            q = cfgcall.measure_via(SOCKS, 20) or cfgcall.assess([])
            S["call"] = dict(q, t=time.time())
            return self.reply(200, {"ok": True, "q": S["call"], "tips": call_tips(q)})
        if p == "/api/call/best":
            if S["stage"] == "connected" and CALL[0]:
                if CALL_SEARCH.locked():
                    CALL_KICK.set()  # جستجو در جریانه (یا منتظر دوره‌ی بعدیه)؛ همین الان دوباره بگرده
                else:
                    threading.Thread(target=call_prepare, args=(GEN[0], CUR[0], True), daemon=True).start()
            return self.reply(200, {"ok": True})
        if p == "/api/start":
            r = start_session(j)
            if not r.get("ok"):
                return self.reply(200, r)
        elif p == "/api/discover":
            if S["stage"] == "connected" and not DISC["running"]:
                threading.Thread(target=discover_sources, kwargs={"force": True}, daemon=True).start()
            else:
                DISC["msg"] = "اول به اینترنت وصل شو (جستجو از داخل تونل انجام می‌شه)."
        elif p == "/api/learn_reset":
            learn_reset()
        elif p == "/api/stop":
            STOP.set()
            if S["stage"] != "running":
                disconnect()
            else:
                S["msg"] = "در حال لغو ..."
        elif p == "/api/clean":
            if PIPE and PIPE.is_alive():  # عملیات جاری نباید بعد از پاک‌سازی دوباره نتیجه بنویسه
                STOP.set()
                PIPE.join(10)
            disconnect(silent=True)
            SITE_CACHE.clear()
            POOL["tiers"] = None
            PREFETCH.update(links=[], stats={}, t=0.0, origin={})
            RUN.clear()
            RUN.update(report.new_stats())
            CUM.clear()
            CUM.update(report.new_stats())
            for fn in ("good.txt", "custom.txt", "cache.txt", "stats.json"):
                try:
                    (DATA / fn).unlink()
                except OSError:
                    pass
            S.update(stage="idle", step=0, pct=0, msg="نتایج پاک شد", connected=None, log=[])
        elif p == "/api/import":
            text = str(j.get("text", ""))[:2_000_000]
            ls = cfgscan.extract_links(text)[:20000]  # سقف؛ متن مخرب نتونه میلیون‌ها لینک بسازه
            urls = cfgscan.sub_urls(text, ls)  # لینک ساب‌اسکریپشن (https) هم قبول می‌شه؛ یک بار دریافت و کانفیگ‌هاش ذخیره می‌شه
            if urls:
                ca = HERE / "cacert.pem"
                if ca.is_file():
                    cfgscan.CA_FILE = str(ca)
                got, _ = cfgscan.fetch_sources(urls, per_source=2500, log=lambda m: None, deadline=30,
                                               proxy_port=HTTP if XRAY_PROC else None)
                ls = ls + got
            ls = [l for l in dict.fromkeys(ls) if cfgscan.parse(l)]
            if ls:
                DATA.mkdir(parents=True, exist_ok=True)
                cp = DATA / "custom.txt"
                saved = write_secret(cp, "\n".join(list(dict.fromkeys(ls + read_links(cp)))[:3000]) + "\n")
                if saved is False:
                    return self.reply(200, {"ok": False, "error": "ذخیره‌ی رمزشده ممکن نشد؛ چیزی ذخیره نشد."})
            res = {"ok": True, "added": len(ls), "urls": len(urls)}
            if not ls and not urls and re.search(r"http://\S", text):
                res["error"] = "http"  # fetch_sources عمداً فقط https می‌گیره
            return self.reply(200, res)
        elif p == "/api/addsource":  # کانال/گروه عمومی پیام‌رسان به‌عنوان منبع کانفیگ
            url, kind = cfgscan.normalize_channel(str(j.get("text", "")))
            if not url:
                return self.reply(200, {"ok": False, "error": cfgscan.CHAN_WHY.get(kind, "لینک درست نیست.")})
            db = load_db()
            if any(x["url"] == url for x in db["sources"]):
                return self.reply(200, {"ok": False, "error": "این کانال قبلاً اضافه شده."})
            ca = HERE / "cacert.pem"
            if ca.is_file():
                cfgscan.CA_FILE = str(ca)
            links, stats = cfgscan.fetch_sources([url], per_source=2500, log=lambda m: None, deadline=45,
                                                 proxy_port=HTTP if XRAY_PROC else None)
            if not links:
                errs = (stats.get(url) or {}).get("errs")
                why = (f"علت: {cfgscan.why_text(stats)}." if errs else
                       "توی پیام‌های اخیرش کانفیگی نبود یا کانال «پیش‌نمایش عمومی» نداره.")
                return self.reply(200, {"ok": False, "error": "چیزی پیدا نشد. " + why})
            db["sources"].append({"url": url, "on": True, "got": len(links), "alive": 0, "kind": "channel", "last_ok": int(time.time())})
            save_db(db)
            return self.reply(200, {"ok": True, "found": len(links)})
        elif p == "/api/sitecheck":  # تست دستی: از اتصال فعلی یوتیوب، اینستاگرام و تلگرام باز می‌شن؟
            if S["stage"] != "connected":
                return self.reply(200, {"ok": False, "error": "اول وصل شو."})
            r = cfgscan.site_check(SOCKS, 6)
            POOL["sites"] = r
            return self.reply(200, {"ok": True, "sites": r})
        elif p == "/api/delsource":
            url = str(j.get("url", ""))
            db = load_db()
            if any(x["url"] == url and x.get("kind") == "auto" for x in db["sources"]):
                db.setdefault("removed", []).append(url)  # دوباره پیشنهاد نشه
            db["sources"] = [x for x in db["sources"] if not (x["url"] == url and x.get("kind") in ("channel", "auto"))]
            save_db(db)
            return self.reply(200, {"ok": True})
        elif p == "/api/closing":
            if time.time() - CLOSING[0] > 2:  # سیل درخواست، ده‌ها نخ نسازه
                CLOSING[0] = time.time()
                threading.Thread(target=closing_check, args=(time.time(),), daemon=True).start()
        elif p == "/api/settings":
            applied = save_settings(j)
            if applied:
                say("تنظیمات: " + " ".join(applied))
            return self.reply(200, {"ok": True, "applied": applied})
        elif p == "/api/hide":
            BG[0] = True
            close_window()
        elif p == "/api/quit":
            threading.Thread(target=quit_app, daemon=True).start()
        elif p == "/api/uninstall":
            threading.Thread(target=quit_app, args=(True,), daemon=True).start()
        return self.reply(200, {"ok": True})


CDP = [False]  # true: کنترل پنجره از طریق پروتکل مرورگر وصله و پرسش «قبل از بسته‌شدن» کار می‌کنه


class _WS:
    """وب‌سوکت خیلی ساده (فقط متن) برای حرف‌زدن با پورت دیباگ مرورگر؛ بدون کتابخانه‌ی بیرونی."""

    def __init__(self, port, path, timeout=10):
        self.s = socket.create_connection(("127.0.0.1", port), timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            c = self.s.recv(4096)
            if not c:
                raise OSError("handshake")
            buf += c
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise OSError("handshake refused")
        self.s.settimeout(None)

    def _need(self, n):
        while len(self.buf) < n:
            c = self.s.recv(65536)
            if not c:
                raise OSError("closed")
            self.buf += c
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def send(self, text):
        data = text.encode()
        hdr = bytearray([0x81])
        n = len(data)
        hdr += bytes([0x80 | n]) if n < 126 else (bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536
                                                  else bytes([0x80 | 127]) + struct.pack(">Q", n))
        mask = os.urandom(4)
        self.s.sendall(bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def recv(self):
        msg = b""
        while True:
            b1, b2 = self._need(2)
            op, n = b1 & 0x0F, b2 & 0x7F
            if n == 126:
                n = struct.unpack(">H", self._need(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._need(8))[0]
            payload = self._need(n)
            if op == 8:
                raise OSError("closed")
            if op == 9:  # ping
                self.s.sendall(bytes([0x8A, 0x80]) + b"\0\0\0\0")
                continue
            if op in (0, 1, 2):
                msg += payload
                if b1 & 0x80:
                    return msg.decode("utf-8", "replace")


def ask_close_choice(stage=""):
    """پرسش قبل از بسته‌شدن پنجره: 'bg' (پس‌زمینه)، 'quit' (بستن کامل) یا 'stay' (برگشت به برنامه)."""
    if os.name != "nt":
        return "bg"
    import ctypes
    now = {"connected": "الان به اینترنت وصلی.", "running": "جستجو در حال انجامه."}.get(stage, "الان اتصالی برقرار نیست.")
    msg = (now + "\nمی‌خوای برنامه در پس‌زمینه به کارش ادامه بده؟\n\n"
           "بله = ادامه در پس‌زمینه (برای دیدن دوباره‌ی پنجره، ConfigTool رو اجرا کن)\n"
           "خیر = بستن کامل و قطع اتصال\nانصراف = برگشت به برنامه")
    try:  # YESNOCANCEL | ICONQUESTION | SETFOREGROUND | TOPMOST | RTLREADING ؛ ۶ بله، ۷ خیر، ۲ انصراف
        r = ctypes.windll.user32.MessageBoxW(0, msg, "ابزار اتصال", 0x23 | 0x10000 | 0x40000 | 0x100000)
    except Exception as e:
        close_log(f"MessageBox exception {type(e).__name__}")
        return "bg"
    close_log(f"MessageBox(before close) result {r}")
    return {7: "quit", 2: "stay"}.get(r, "bg")  # هر چیز غیرمنتظره = اتصال نمونه قطع نشه


def cdp_guard(proc, url):
    """به پورت دیباگ پنجره وصل می‌شه تا وقتی کاربر ضربدر رو زد، قبل از بسته‌شدن پنجره (پیام beforeunload) ازش بپرسه."""
    ws = None
    try:
        af = DATA / "browser" / "DevToolsActivePort"
        t0 = time.time()
        while not af.exists() and time.time() - t0 < 20 and proc.poll() is None:
            time.sleep(0.2)
        lines = af.read_text(encoding="utf-8").split()
        ws = _WS(int(lines[0]), lines[1])
        seq = [0]

        def call(method, params=None, sid=None):
            seq[0] += 1
            m = {"id": seq[0], "method": method, "params": params or {}}
            if sid:
                m["sessionId"] = sid
            ws.send(json.dumps(m))
            return seq[0]

        def wait_for(i):
            while True:
                r = json.loads(ws.recv())
                if r.get("id") == i:
                    return r.get("result") or {}

        sid = None
        for _ in range(40):  # صفحه‌ی خود برنامه باید پیدا بشه
            r = wait_for(call("Target.getTargets"))
            for t in r.get("targetInfos", []):
                if t.get("type") == "page" and f"127.0.0.1:{PORT}" in t.get("url", ""):
                    sid = wait_for(call("Target.attachToTarget", {"targetId": t["targetId"], "flatten": True})).get("sessionId")
                    break
            if sid:
                break
            time.sleep(0.5)
        if not sid:
            return close_log("cdp: page not found")
        wait_for(call("Page.enable", sid=sid))
        CDP[0] = True
        close_log("cdp attached")
        while True:
            r = json.loads(ws.recv())
            if r.get("method") != "Page.javascriptDialogOpening" or (r.get("params") or {}).get("type") != "beforeunload":
                continue
            accept, choice = True, "bg"  # هر خطایی پیش بیاد پنجره گیر نکنه و بسته بشه
            try:
                ASKING[0] = True
                choice = ask_close_choice(S["stage"])
                accept = choice != "stay"
            finally:
                try:
                    call("Page.handleJavaScriptDialog", {"accept": accept}, sid)
                except Exception:
                    pass
                ASKING[0] = False
            if choice == "bg":
                BG[0] = True
                close_log("continuing in background")
            elif choice == "quit":
                close_log("quitting (asked before close)")
                threading.Thread(target=quit_app, daemon=True).start()
    except Exception as e:
        CDP[0] = False
        close_log(f"cdp stopped: {type(e).__name__}")
    finally:
        try:
            ws and ws.s.close()
        except Exception:
            pass



EMBEDDED = bool(os.environ.get("CFG_EMBEDDED"))  # پنجره‌ی خود لانچر (WebView2) نشون می‌ده، نه مرورگر


def open_window(url):
    global WIN
    if ANDROID:  # رابط داخل خود برنامه (WebView) است؛ آدرس/توکن هم لاگ نمی‌شود
        return
    BG[0] = False
    if EMBEDDED:  # لانچر آدرس رو از این فایل می‌خونه و پنجره‌ی خودش رو می‌سازه
        BG[0] = True  # بسته‌شدن پنجره رو لانچر مدیریت می‌کنه، نه تایمر
        try:
            tmp = DATA / "url.tmp"
            tmp.write_text(url, encoding="utf-8")
            os.replace(tmp, DATA / "url.txt")
        except OSError:
            pass
        return
    if os.environ.get("NOWINDOW"):
        print(url, flush=True)
        return
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        b = os.environ.get(env)
        for rel in ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe"):
            if b and (Path(b) / rel).exists():
                try:
                    (DATA / "browser" / "DevToolsActivePort").unlink()
                except OSError:
                    pass
                WIN = subprocess.Popen([str(Path(b) / rel), f"--app={url}", f"--user-data-dir={DATA / 'browser'}",
                                        "--remote-debugging-port=0",
                                        "--window-size=470,900", "--no-first-run", "--no-default-browser-check",
                                        "--disable-background-mode", "--disable-background-timer-throttling",
                                        "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows"])
                threading.Thread(target=cdp_guard, args=(WIN, url), daemon=True).start()
                return
    webbrowser.open(url)


def close_log(text):
    """ردپای کوتاه برای عیب‌یابی بسته‌شدن (فقط زمان و نتیجه؛ هیچ آدرس یا رمزی نیست)."""
    try:
        with open(DATA / "close.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + text + "\n")
    except OSError:
        pass


def ask_background(stage=""):
    """پنجره بسته شده ولی اتصال یا جستجو فعاله: می‌پرسه در پس‌زمینه ادامه بده یا کامل ببنده."""
    if os.name != "nt":
        return False
    import ctypes
    now = {"connected": "الان به اینترنت وصلی.", "running": "جستجو در حال انجامه."}.get(stage, "الان اتصالی برقرار نیست.")
    msg = (now + "\nمی‌خوای برنامه در پس‌زمینه به کارش ادامه بده؟\n\n"
           "بله = ادامه در پس‌زمینه (اتصال و جستجو ادامه دارن؛ برای دیدن دوباره‌ی پنجره، ConfigTool رو اجرا کن)\n"
           "خیر = بستن کامل و قطع اتصال")
    # YESNO | ICONQUESTION | SETFOREGROUND | TOPMOST | RTLREADING ؛ ۶ یعنی «بله»، ۷ یعنی «خیر»
    try:
        r = ctypes.windll.user32.MessageBoxW(0, msg, "ابزار اتصال", 0x24 | 0x10000 | 0x40000 | 0x100000)
    except Exception as e:
        close_log(f"MessageBox exception {type(e).__name__}")
        return True  # اگه نتونست بپرسه، اتصال رو قطع نکنه
    close_log(f"MessageBox result {r}")
    return r != 7  # فقط «خیر» صریح کامل می‌بنده؛ اگه پنجره‌ی پرسش نشون داده نشد (۰) هم اتصال می‌مونه


def close_window():
    global WIN
    if WIN is not None:
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(WIN.pid), "/T", "/F"], capture_output=True, creationflags=0x08000000)
            else:
                WIN.terminate()
        except Exception:
            pass
    WIN = None


def closing_check(t):
    """صفحه بسته شد (pagehide)؛ اگه تا ۳ ثانیه دوباره زنده نشد (رفرش نبود) یعنی پنجره واقعاً بسته شده."""
    time.sleep(3)
    if S["beat"] > t or BG[0] or ASKING[0] or QUITTING[0]:
        return
    ASKING[0] = True
    try:
        on_window_closed()
    finally:
        ASKING[0] = False


def on_window_closed():
    close_log(f"window closed, stage={S['stage']}")
    if ask_background(S["stage"]):  # همیشه می‌پرسه، حتی وقتی اتصالی نیست
        BG[0] = True
        close_window()
        close_log("continuing in background")
    else:
        close_log("quitting")
        quit_app()


def watchdog():
    global XRAY_PROC
    t0 = time.time()
    while True:
        time.sleep(0.3)  # تند، تا اگه پنجره بدون پرسش قبلی بسته شد، پرسش فوری بیاد
        if XRAY_PROC and XRAY_PROC.poll() is not None and S["stage"] == "connected" and not FAILOVER.is_set():
            T.evt("core_died", f"هسته‌ی اتصال متوقف شد (کد خروج {XRAY_PROC.returncode})")
            T.incident("core_died", rc=XRAY_PROC.returncode, **_inc_state())
            XRAY_PROC = None
            restore_proxy()
            S.update(stage="error", msg="هسته‌ی اتصال متوقف شد. دوباره دکمه‌ی اتصال رو بزن.", connected=None)
        if WIN is not None and time.time() - t0 > 8 and WIN.poll() is not None and not ASKING[0] and not BG[0] and not QUITTING[0]:
            ASKING[0] = True  # پنجره بسته شد (نه اینکه مرورگر تایمرها رو کند کرده)
            try:
                on_window_closed()
            finally:
                ASKING[0] = False
        elif WIN is None and not BG[0] and time.time() - S["beat"] > 900:
            quit_app()


def _proc_is_ours(pid):
    """PID ذخیره‌شده بعد از کرش یا ریبوت ممکنه به برنامه‌ی دیگه‌ای رسیده باشه؛ فقط اگه واقعاً xray یا sing-box است بکش."""
    try:
        if ANDROID:
            return any(k in Path(f"/proc/{pid}/cmdline").read_bytes() for k in (b"libxray", b"libsingbox"))
        if os.name == "nt":
            r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"], capture_output=True, timeout=8,
                               creationflags=0x08000000)
            out = r.stdout.decode("mbcs", "replace").lower()
            return any(f'"{n}.exe"' in out for n in ("xray", "sing-box"))
        p = Path(f"/proc/{pid}/cmdline")
        if p.exists():
            name = os.path.basename(p.read_bytes().split(b"\0")[0].decode("utf-8", "replace"))
        else:  # مک
            name = os.path.basename(subprocess.run(["ps", "-p", str(pid), "-o", "comm="], capture_output=True, timeout=8)
                                    .stdout.decode().strip())
        return name in ("xray", "sing-box")
    except Exception:
        return False


def _timed(fn):
    def w(self):
        t0 = time.time()
        try:
            return fn(self)
        finally:
            try:
                route = (self.path or "").split("?")[0]
                T.perf("http_state" if route == "/api/state" else "http_api" if route.startswith("/api/") else "http_page", time.time() - t0)
                if route == "/api/state":
                    now = time.time()
                    g = now - HTTPS["last_state_t"] if HTTPS["last_state_t"] else None
                    HTTPS["last_state_t"] = now
                    if g is not None and g < 120:
                        T.perf("ui_state_gap", g)  # فاصله‌ی دو درخواست وضعیت پشت‌سرهم (برای دیدن تأخیر همگام‌سازی صفحه)
            except Exception:
                pass
    return w


H.do_GET, H.do_POST = _timed(H.do_GET), _timed(H.do_POST)


def main():
    global PORT, TOKEN, _lock
    DATA.mkdir(parents=True, exist_ok=True)
    # اول قفل تک‌نمونه‌ای؛ تا مطمئن نشدیم نمونه‌ی دیگه‌ای نیست، به PID و پراکسی دست نمی‌زنیم
    _lock = socket.socket()
    try:
        if not ANDROID:
            _lock.bind(("127.0.0.1", LOCK_PORT))
    except OSError:  # نسخه‌ی دیگه‌ای در حال اجراست؛ همون پنجره رو دوباره باز کن
        try:
            open_window(json.loads((DATA / "run.json").read_text(encoding="utf-8"))["url"])
        except Exception:
            pass
        return
    try:  # xray یتیمِ دفعه‌ی قبل (اگه برنامه ناگهانی بسته شده) پورت رو اشغال نکنه
        pid = int((DATA / "xray.pid").read_text(encoding="utf-8").strip())
        if not _proc_is_ours(pid):
            (DATA / "xray.pid").unlink()
            raise OSError("not ours")  # شناسه‌ی فرایند عوض شده؛ چیز دیگه‌ای رو نکش
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=0x08000000)
        else:
            os.kill(pid, 9)
        (DATA / "xray.pid").unlink()
    except Exception:
        pass
    CUM.update(report.load(STATS_FILE))
    cfgdata.load(str(DATA / "data.json"))
    load_block()
    load_localblock()
    restore_proxy()  # اگه دفعه‌ی قبل ناگهانی بسته شده بود، تنظیم قبلی پروکسی برمی‌گرده
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    PORT, TOKEN = srv.server_address[1], secrets.token_urlsafe(16)
    url = f"http://127.0.0.1:{PORT}/?t={TOKEN}"
    rj = DATA / "run.json"
    rj.write_text(json.dumps({"url": url}), encoding="utf-8")
    os.chmod(rj, 0o600)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=net_watch, daemon=True).start()
    threading.Thread(target=series_loop, daemon=True).start()
    atexit.register(shutdown)
    S["beat"] = time.time()
    threading.Thread(target=startup_refresh, daemon=True).start()
    threading.Thread(target=daily_refresh, daemon=True).start()
    if _ev:
        _ev.hook_errors()  # خطاهای کنترل‌نشده برای گزارش ثبت می‌شن
        _ev.confirm_later()  # چند ثانیه سالم موندن = وصله‌ی تازه تأیید می‌شه
        threading.Thread(target=_ev.enforce, daemon=True).start()
    open_window(url)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
