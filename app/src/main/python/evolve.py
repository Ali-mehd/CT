#!/usr/bin/env python3
"""evolve - تکامل امن برنامه (این فایل «محافظ»ه و هیچ وصله‌ای حق تغییرش رو نداره).

چهار کار:
  ۱. گزارش: آمار کلی و بی‌خطر (بدون آدرس سرور، رمز و توکن) که فشرده و مهر می‌شه تا به Claude بدی.
  ۲. وصله: فایل .ctpatch که Claude می‌سازه. اول فقط بررسی می‌شه، بعد توی یک کپی جدا (stage) با همه‌ی تست‌ها امتحان
     می‌شه و فقط اگه همه‌چیز سالم بود جای فایل‌های اصلی می‌شینه. نسخه‌ی قبلی نگه داشته می‌شه و برگشت خودکاره.
  ۳. سقف حجم: پوشه‌ی تکامل از سقف انتخابی بزرگ‌تر نمی‌شه؛ قدیمی‌ترین پشتیبان‌ها و گزارش‌ها اول پاک می‌شن.
  ۴. تنظیم خودکار تعداد تست هم‌زمان (نه سرعت ارسال، که چیزی که اپراتور می‌بینه همونه که کاربر انتخاب کرده).

فقط کتابخانه‌ی استاندارد پایتون."""
import base64, hashlib, io, json, os, platform, re, secrets, shutil, subprocess, sys, tempfile, threading, time, traceback, zipfile, zlib
from pathlib import Path

FMT = 1
MAX_PATCH = 3_000_000        # حجم فایل zip وصله
MAX_UNPACKED = 8_000_000     # مجموع حجم بعد از باز شدن (ضد zip-bomb)
MAX_FILE = 2_500_000
MAX_FILES = 40
CODE_MAX = 4_000_000         # سقف مجموع کد برنامه (فایل‌های app/*.py|html|txt)
CAP_DEFAULT, CAP_MIN, CAP_MAX = 20, 5, 100   # مگابایت؛ سقف پوشه‌ی تکامل
KEEP = 3                     # چند نسخه‌ی پشتیبان نگه داشته بشه
REPORT_TTL = 30 * 86400      # وصله فقط برای گزارش‌های کمتر از ۳۰ روز قبول می‌شه
GATE_TIMEOUT, GATE_TOTAL = 150, 600
APP_RE = re.compile(r"^app/[A-Za-z0-9_\-]{1,40}\.(py|html|txt)$")
TEST_RE = re.compile(r"^tests/t[A-Za-z0-9_\-]{1,40}\.py$")
PROTECTED = {"app/evolve.py"}
GUARD = "# [evolve-guard]"
TUNE_MIN, TUNE_MAX = 0.6, 1.4

ROOT = DATA = None
_lock = threading.RLock()
JOB = {"state": "idle", "msg": "", "steps": [], "t": 0}


class PatchError(Exception):
    pass


# ------------------------------------------------------------ مسیرها و وضعیت
def E():
    return DATA / "evolve"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _fsha(p):
    try:
        return _sha(Path(p).read_bytes())
    except OSError:
        return None


def _atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp%d" % os.getpid())
    tmp.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    os.replace(tmp, path)


def _default():
    return {"v": 1, "ver": "", "cap_mb": CAP_DEFAULT, "autotune": True, "applied": [], "reports": {},
            "boot_tries": 0, "tune": {"m": 1.0, "hist": [], "why": ""}, "log": []}


def _load():
    try:
        d = json.loads((E() / "state.json").read_text(encoding="utf-8"))
        if not isinstance(d, dict):
            raise ValueError
    except Exception:
        d = {}
    base = _default()
    for k, v in base.items():
        if not isinstance(d.get(k), type(v)):
            d[k] = v
    d["cap_mb"] = min(CAP_MAX, max(CAP_MIN, int(d["cap_mb"]))) if isinstance(d["cap_mb"], (int, float)) else CAP_DEFAULT
    t = d["tune"]
    t["m"] = min(TUNE_MAX, max(TUNE_MIN, float(t.get("m", 1.0)))) if isinstance(t.get("m"), (int, float)) else 1.0
    t["hist"] = t["hist"] if isinstance(t.get("hist"), list) else []
    return d


def _save(st):
    _atomic(E() / "state.json", json.dumps(st, ensure_ascii=False))


def _log(st, msg):
    st["log"] = (st["log"] + [[int(time.time()), msg]])[-40:]


def _app_ver():
    try:
        return (ROOT / "version.txt").read_text(encoding="utf-8").strip() or "dev"
    except OSError:
        return "dev"


def init(root, data):
    """مسیرها رو می‌گیره و وضعیت رو با فایل‌های واقعی هماهنگ می‌کنه (مثلاً بعد از به‌روزرسانی برنامه وصله‌ها دیگه معتبر نیستن)."""
    global ROOT, DATA
    ROOT, DATA = Path(root), Path(data)
    with _lock:
        st = _load()
        ver = _app_ver()
        if st["ver"] and st["ver"] != ver:  # نسخه‌ی تازه‌ی برنامه نصب شده؛ فایل‌های اصلی دوباره باز شدن
            _log(st, "نسخه‌ی برنامه عوض شد؛ وصله‌ها و پشتیبان‌های قبلی کنار گذاشته شدن.")
            st["applied"], st["boot_tries"] = [], 0
            for d in ("versions", "original"):
                shutil.rmtree(E() / d, ignore_errors=True)
        st["ver"] = ver
        exp = {}
        for a in st["applied"]:  # آخرین وصله‌ی فعالِ هر فایل تعیین می‌کنه فایل الان باید چه محتوایی داشته باشه
            if a.get("active"):
                for f in a.get("files", []):
                    exp[f["path"]] = f.get("after")
        stale = {p for p, h in exp.items() if _fsha(ROOT / p) != h}  # فایل از بیرون برگشته یا عوض شده (مثلاً راه‌انداز دوباره باز کرد)
        for a in st["applied"]:
            if a.get("active") and any(f["path"] in stale for f in a.get("files", [])):
                a["active"] = False
                _log(st, f"وصله‌ی «{a.get('title', '')}» دیگه روی فایل‌ها نیست (برنامه برگشته به حالت قبل).")
        try:
            _save(st)
        except OSError:
            pass


def _py():
    """پایتونی که تست‌ها باهاش اجرا می‌شه؛ نسخه‌ی بدون پنجره (pythonw) خروجی نمی‌ده، پس اگه python.exe هست اون."""
    exe = Path(sys.executable)
    if exe.name.lower().startswith("pythonw"):
        c = exe.with_name("python.exe")
        if c.is_file():
            return str(c)
    return str(exe)


# ------------------------------------------------------------ پاک‌سازی متن برای گزارش
_RX = [
    (re.compile(r"[a-z][a-z0-9+.\-]{1,12}://[^\s\"'<>]+", re.I), "<url>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<id>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b", re.I), "<ip6>"),
    (re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+"), "<mail>"),
    (re.compile(r"[A-Za-z]:\\[^\s\"']+|/(?:home|Users|root)/[^\s\"']+"), "<path>"),
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), "<token>"),
]


def scrub(s):
    s = str(s)
    for rx, rep in _RX:
        s = rx.sub(rep, s)
    return s[:300]


def _clean(o, depth=0):
    if depth > 6:
        return None
    if isinstance(o, str):
        return scrub(o)
    if isinstance(o, bool) or o is None:
        return o
    if isinstance(o, (int, float)):
        return o if o == o and abs(o) < 1e15 else 0
    if isinstance(o, dict):
        return {scrub(k)[:60]: _clean(v, depth + 1) for k, v in list(o.items())[:300]}
    if isinstance(o, (list, tuple, set)):
        return [_clean(v, depth + 1) for v in list(o)[:300]]
    return None


# ------------------------------------------------------------ گزارش
def _appdir():
    """پوشه‌ی کد برنامه. توی اندروید فایل‌ها توی پوشه‌ی تخت کنار همین فایل‌اند (نه ROOT/app)؛ اونجا فقط گزارش کار می‌کنه."""
    d = ROOT / "app"
    return d if d.is_dir() else Path(__file__).resolve().parent


def code_files():
    out = []
    try:
        for p in sorted(_appdir().iterdir()):
            if p.is_file() and p.suffix in (".py", ".html", ".txt") and p.name not in ("blocklist.txt", "snapshot.txt"):
                b = p.read_bytes()
                out.append({"path": "app/" + p.name, "sha256": _sha(b), "lines": b.count(b"\n"), "size": len(b)})
    except OSError:
        pass
    return out


def code_size():
    try:
        return sum(p.stat().st_size for p in _appdir().iterdir()
                   if p.is_file() and p.suffix in (".py", ".html", ".txt") and p.name not in ("blocklist.txt", "snapshot.txt"))
    except OSError:
        return 0


def _dirsize(p):
    n = 0
    for r, _, fs in os.walk(p):
        for f in fs:
            try:
                n += os.path.getsize(os.path.join(r, f))
            except OSError:
                pass
    return n


def usage():
    st = _load()
    return {"code": code_size(), "code_max": CODE_MAX, "evolve": _dirsize(E()), "data": _dirsize(DATA),
            "cap": st["cap_mb"] * 1_000_000}


# ------------------------------------------------------------ اطلاعات سیستم و خطاها
ERRORS = []  # آخرین خطاهای کنترل‌نشده؛ فقط نوع خطا، پیام پاک‌شده و «فایل:خط تابع»
_err_lock = threading.Lock()


def note_error(where, exc):
    """خطایی که برنامه نگرفته بود رو ثبت می‌کنه (برای گزارش). هیچ چیزی خارج از برنامه فرستاده نمی‌شه."""
    try:
        tb = traceback.extract_tb(getattr(exc, "__traceback__", None))[-4:]
        row = {"t": int(time.time()), "where": scrub(where)[:60], "type": type(exc).__name__, "msg": scrub(exc)[:160],
               "at": [f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in tb]}
        with _err_lock:
            ERRORS.append(row)
            del ERRORS[:-60]
    except Exception:
        pass


def hook_errors():
    old_t, old_s = threading.excepthook, sys.excepthook

    def th(a):
        note_error("thread:" + str(getattr(a.thread, "name", "?")), a.exc_value)
        old_t(a)

    def se(t, v, tb):
        note_error("main", v)
        old_s(t, v, tb)
    threading.excepthook, sys.excepthook = th, se


def _mem():
    try:
        if os.name == "nt":
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_ulong), ("load", ctypes.c_ulong)] + [(n, ctypes.c_ulonglong) for n in ("tp", "ap", "tpf", "apf", "tv", "av", "ax")]
            m = MS()
            m.l = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            return {"total_mb": m.tp // 2 ** 20, "free_mb": m.ap // 2 ** 20, "load_pct": m.load}
        d = {}
        for l in open("/proc/meminfo", encoding="utf-8"):
            k, _, v = l.partition(":")
            if k in ("MemTotal", "MemAvailable"):
                d[k] = int(v.split()[0]) // 1024
        return {"total_mb": d.get("MemTotal"), "free_mb": d.get("MemAvailable")}
    except Exception:
        return {}


def _tool(rel, args):
    p = ROOT / rel
    if not p.is_file():
        return {"present": False}
    b = p.read_bytes()
    o = {"present": True, "size": len(b), "sha256_16": _sha(b)[:16]}
    try:
        r = subprocess.run([str(p)] + args, capture_output=True, text=True, timeout=6, creationflags=0x08000000 if os.name == "nt" else 0)
        o["version"] = scrub((r.stdout or r.stderr).strip().splitlines()[0])[:80] if (r.stdout or r.stderr).strip() else ""
    except Exception as e:
        o["version"] = "?" + type(e).__name__
    return o


def _log_tail(n=150):
    out = []
    for name in ("launcher.log",):
        try:
            ls = (ROOT / name).read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
            out.append({"file": name, "lines": [scrub(l) for l in ls]})
        except OSError:
            pass
    return out


def sysinfo():
    """مشخصات سیستم و برنامه، بدون هیچ چیز شخصی (نام کاربر، مسیر، IP، نام دستگاه نمی‌آد)."""
    s = {"os": platform.system(), "release": platform.release(), "version": platform.version(), "machine": platform.machine(),
         "cpu_count": os.cpu_count(), "python": platform.python_version(), "python_impl": platform.python_implementation(),
         "embedded": bool(os.environ.get("CFG_EMBEDDED")), "android": bool(os.environ.get("CFG_ANDROID")),
         "tz": time.tzname, "utc_offset_h": round(-time.timezone / 3600, 1), "lang": os.environ.get("LANG") or os.environ.get("LC_ALL") or "",
         "mem": _mem(), "now": time.strftime("%Y-%m-%d %H:%M:%S")}
    try:
        du = shutil.disk_usage(DATA)
        s["disk"] = {"total_gb": round(du.total / 2 ** 30, 1), "free_gb": round(du.free / 2 ** 30, 1)}
    except OSError:
        pass
    if os.name == "nt":
        try:
            import ctypes
            s["admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
        try:
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            s["system_proxy_on"] = bool(winreg.QueryValueEx(k, "ProxyEnable")[0])
        except Exception:
            pass
    s["tools"] = {"xray": _tool("xray/xray.exe" if os.name == "nt" else "xray/xray", ["-version"]),
                  "singbox": _tool("singbox/sing-box.exe" if os.name == "nt" else "singbox/sing-box", ["version"])}
    files = []
    try:
        now = time.time()
        for p in sorted(DATA.iterdir()):
            if p.is_file():
                st = p.stat()
                files.append({"name": scrub(p.name)[:40], "kb": round(st.st_size / 1000, 1), "age_h": round((now - st.st_mtime) / 3600, 1)})
    except OSError:
        pass
    s["data_files"] = files[:60]
    with _err_lock:
        s["errors"] = list(ERRORS)
    s["logs"] = _log_tail()
    return s


def _metrics(ctx):
    cum = ctx.get("stats") or {}
    t, a, r = cum.get("tested", 0) or 0, cum.get("alive", 0) or 0, cum.get("reach", 0) or 0
    fails = cum.get("fails") or {}
    m = {"tested": t, "alive": a, "alive_rate": round(a / t, 4) if t else None, "reach_rate": round(r / t, 4) if t else None,
         "top_fails": sorted(fails.items(), key=lambda kv: -(kv[1] if isinstance(kv[1], (int, float)) else 0))[:5]}
    srcs = ctx.get("sources") or []
    m["sources_total"] = len(srcs)
    m["sources_weak"] = [s.get("url") for s in srcs if isinstance(s, dict) and s.get("on") and (s.get("yield") or 1) < 0.01][:10]
    return m


def make_report(ctx, plain=False):
    """گزارش بی‌خطر. ctx رو هسته می‌سازه؛ هر چیزی که توش باشه قبل از ذخیره از فیلتر آدرس/شناسه/IP/توکن رد می‌شه."""
    with _lock:
        st = _load()
        rid = secrets.token_hex(6)
        st["reports"][rid] = int(time.time())
        for k in sorted(st["reports"], key=st["reports"].get)[:-8]:
            st["reports"].pop(k, None)
        _save(st)
    ctx = _clean(ctx or {})
    rep = {"fmt": FMT, "kind": "ctreport", "id": rid, "created": time.strftime("%Y-%m-%d %H:%M:%S"),
           "app": {"ver": _app_ver(), "python": platform.python_version(), "os": platform.system() + " " + platform.release()},
           "code": code_files(),
           "evolve": {"cap_mb": st["cap_mb"], "autotune": st["autotune"], "tune_m": st["tune"]["m"],
                      "tune_runs": len(st["tune"]["hist"]), "tune_hist": st["tune"]["hist"][-12:],
                      "applied": [{"id": a["id"], "title": a.get("title", ""), "active": a.get("active", False), "ok": a.get("ok", False)}
                                  for a in st["applied"][-10:]],
                      "usage": usage()},
           "system": sysinfo(), "metrics": _metrics(ctx), "ctx": ctx}
    return rid, (_plain(rep) if plain else _seal(rep))


_HEAD = ("=== گزارش ConfigTool (فشرده و مهرشده) ===\n"
         "این فایل آمار کامل برنامه و سیستمه، ولی هیچ آدرس سرور، رمز، توکن، IP یا نام شخصی توش نیست.\n"
         "کل فایل رو توی چت Claude بفرست. اگه چت اجرای کد نداره، به‌جاش «گزارش متنی» رو بفرست.\n"
         "رمزگشایی با پایتون: python3 -c \"import sys,base64,zlib;t=open(sys.argv[1],encoding='utf-8').read().rsplit('CTREPORT1',1)[1].split('SHA256:')[0];print(zlib.decompress(base64.b64decode(''.join(t.split()))).decode())\" فایل\n")


def _seal(obj):
    raw = zlib.compress(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), 9)
    b64 = base64.b64encode(raw).decode()
    lines = "\n".join(b64[i:i + 76] for i in range(0, len(b64), 76))
    return f"{_HEAD}CTREPORT1\n{lines}\nSHA256:{_sha(b64.encode())}\n"


def _plain(obj):
    """همان گزارش به‌صورت متن خوانا (JSON)، برای چت‌هایی که فایل فشرده رو نمی‌تونن باز کنن."""
    return ("=== گزارش ConfigTool (متنی) ===\nآمار کامل برنامه و سیستم؛ بدون آدرس سرور، رمز، توکن، IP یا نام شخصی.\n"
            "کل فایل رو توی چت Claude بفرست.\nCTREPORT-PLAIN1\n" + json.dumps(obj, ensure_ascii=False, indent=1) + "\n")


def open_report(text):
    """برعکس _seal؛ مهر رو چک می‌کنه (خرابی یا دستکاری رو نشون می‌ده)."""
    if "\nCTREPORT-PLAIN1\n" in "\n" + str(text):
        return json.loads(str(text).split("CTREPORT-PLAIN1\n", 1)[1])
    ls = [l.strip() for l in str(text).splitlines()]
    try:
        i = ls.index("CTREPORT1")
    except ValueError:
        raise PatchError("این فایل گزارش ConfigTool نیست.")
    body = []
    for l in ls[i + 1:]:
        if l.startswith("SHA256:"):
            want = l[7:].strip()
            break
        body.append(l)
    else:
        raise PatchError("گزارش ناقصه (خط مهر پیدا نشد).")
    b64 = "".join(body)
    if _sha(b64.encode()) != want:
        raise PatchError("مهر گزارش نمی‌خونه؛ فایل خراب یا دستکاری شده.")
    d = zlib.decompressobj()
    raw = d.decompress(base64.b64decode(b64), 4_000_000)
    if d.unconsumed_tail:
        raise PatchError("گزارش بیش از حد بزرگه.")
    return json.loads(raw.decode("utf-8"))


# ------------------------------------------------------------ خواندن و بررسی وصله
def _stdlib():
    return set(getattr(sys, "stdlib_module_names", ())) | set(sys.builtin_module_names)


def _read_patch(data):
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_PATCH:
        raise PatchError("فایل وصله خیلی بزرگه یا خالیه.")
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(data)))
        infos = z.infolist()
    except Exception:
        raise PatchError("فایل وصله خرابه یا از نوع درست نیست.")
    if len(infos) > MAX_FILES + 2 or sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise PatchError("وصله بیش از حد بزرگه.")
    for i in infos:
        n = i.filename
        if n.startswith("/") or "\\" in n or ".." in n.split("/") or i.file_size > MAX_FILE:
            raise PatchError("مسیر یا اندازه‌ی یکی از فایل‌های وصله مجاز نیست.")
    try:
        man = json.loads(z.read("manifest.json").decode("utf-8"))
    except Exception:
        raise PatchError("فهرست وصله (manifest) خرابه.")
    if not isinstance(man, dict) or man.get("fmt") != FMT or not isinstance(man.get("files"), list) or not man["files"]:
        raise PatchError("فهرست وصله با این نسخه‌ی برنامه سازگار نیست.")
    files = {}
    for f in man["files"]:
        if not isinstance(f, dict) or not isinstance(f.get("path"), str) or f.get("action") not in ("replace", "add"):
            raise PatchError("یکی از ردیف‌های فهرست وصله درست نیست.")
        try:
            b = z.read("files/" + f["path"])
        except KeyError:
            raise PatchError(f"فایل {f['path']} توی وصله نیست.")
        if _sha(b) != f.get("sha256"):
            raise PatchError(f"مهر فایل {f['path']} نمی‌خونه (دستکاری یا خرابی).")
        if f["path"] in files:
            raise PatchError("یک فایل دوبار توی وصله اومده.")
        files[f["path"]] = b
    return man, files


def inspect_patch(data):
    """فقط بررسی؛ هیچ چیزی تغییر نمی‌کنه. خروجی: dict با ok و errors و summary (برای نمایش به کاربر)."""
    errs, summary = [], {}
    try:
        man, files = _read_patch(data)
    except PatchError as e:
        return {"ok": False, "errors": [str(e)], "summary": {}}
    st = _load()
    now = time.time()
    rid = str(man.get("report_id", ""))
    if rid not in st["reports"]:
        errs.append("این وصله برای گزارشی ساخته شده که از همین برنامه نیست (یا قبلاً استفاده شده).")
    elif now - st["reports"][rid] > REPORT_TTL:
        errs.append("گزارشِ این وصله بیش از ۳۰ روز پیشه؛ یک گزارش تازه بساز.")
    if str(man.get("app_ver", "")) not in ("", _app_ver()):
        errs.append("این وصله برای نسخه‌ی دیگه‌ای از برنامه ساخته شده.")
    base = man.get("base") if isinstance(man.get("base"), dict) else {}
    std = _stdlib()
    rows, total_new = [], code_size()
    for f in man["files"]:
        p, act, b = f["path"], f["action"], files[f["path"]]
        ap = ROOT / p
        old = ap.read_bytes() if ap.is_file() else None
        if p in PROTECTED:
            errs.append(f"{p} محافظه و وصله حق تغییرش رو نداره.")
            continue
        is_app, is_test = bool(APP_RE.match(p)), bool(TEST_RE.match(p))
        if not (is_app or is_test):
            errs.append(f"مسیر {p} مجاز نیست.")
            continue
        if is_test and act != "add":
            errs.append("تست‌های موجود قابل تغییر نیستن؛ فقط تست تازه می‌شه اضافه کرد.")
            continue
        if act == "replace":
            if old is None:
                errs.append(f"{p} روی این نسخه وجود نداره (برای جایگزینی).")
                continue
            if base.get(p) != _sha(old):
                errs.append(f"{p} با فایلی که وصله براش ساخته شده فرق داره (احتمالاً وصله‌ی دیگه‌ای قبلاً روش نشسته). گزارش تازه بساز.")
                continue
        else:
            if old is not None:
                errs.append(f"{p} از قبل وجود داره؛ باید «جایگزینی» باشه.")
                continue
            if p.endswith(".py") and p.split("/")[-1][:-3] in std:
                errs.append(f"نام {p} با ماژول‌های خود پایتون یکیه و جایگزینشون می‌شد.")
                continue
        if p.endswith(".py"):
            try:
                compile(b, p, "exec")
            except (SyntaxError, ValueError) as e:
                errs.append(f"{p}: خطای نوشتاری کد ({type(e).__name__}).")
                continue
            if p == "app/cfgweb.py" and (GUARD.encode() not in b or b"early_guard" not in b):
                errs.append("cfgweb.py باید بخش محافظ تکامل رو نگه داره.")
                continue
        if p == "app/ui.html" and (b"__T__" not in b or b"<script>" not in b):
            errs.append("ui.html خراب به‌نظر می‌رسه (نشانه‌های لازم رو نداره).")
            continue
        total_new += len(b) - (len(old) if old else 0)
        rows.append({"path": p, "action": act, "old_lines": old.count(b"\n") if old else 0, "new_lines": b.count(b"\n"),
                     "size": len(b)})
    if total_new > CODE_MAX:
        errs.append(f"با این وصله کد برنامه از سقف {CODE_MAX // 1_000_000} مگابایت بیشتر می‌شه.")
    summary = {"id": str(man.get("id", ""))[:40], "title": str(man.get("title", ""))[:120], "notes": str(man.get("notes", ""))[:2000],
               "files": rows, "code_after": total_new, "code_max": CODE_MAX}
    return {"ok": not errs, "errors": errs, "summary": summary}


# ------------------------------------------------------------ اتاق تست (محدوده‌ی ایزوله)
def _step(msg):
    JOB["steps"].append(msg)
    JOB["msg"] = msg


def _gate(stage):
    """همه‌ی تست‌ها روی کپی جدا اجرا می‌شن، بدون اینترنت و بدون دست زدن به داده‌ی اصلی. خروجی: (ok, توضیح)."""
    app, tests = stage / "app", stage / "tests"
    _step("بررسی نوشتار همه‌ی فایل‌های کد ...")
    for p in sorted(app.glob("*.py")):
        try:
            compile(p.read_bytes(), p.name, "exec")
        except (SyntaxError, ValueError) as e:
            return False, f"{p.name}: خطای نوشتاری ({type(e).__name__})"
    ts = sorted(tests.glob("t*.py")) if tests.is_dir() else []
    if not ts:
        return False, "فایل تست کنار برنامه پیدا نشد؛ بدون تست نصب نمی‌کنم."
    t_end = time.time() + GATE_TOTAL
    for i, t in enumerate(ts, 1):
        _step(f"اجرای تست {i} از {len(ts)} ({t.name}) ...")
        tmp = tempfile.mkdtemp(prefix="ctgate")
        env = dict(os.environ, CFG_DATA=tmp, CFG_NO_RESTART="1", PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")
        env.pop("CFG_EMBEDDED", None)
        try:
            r = subprocess.run([_py(), "-X", "utf8", str(t)], cwd=str(app), env=env, capture_output=True, text=True,
                               timeout=max(5, min(GATE_TIMEOUT, t_end - time.time())),
                               creationflags=0x08000000 if os.name == "nt" else 0)
        except subprocess.TimeoutExpired:
            return False, f"{t.name} زیادی طول کشید"
        except OSError as e:
            return False, f"نشد تست رو اجرا کنم ({type(e).__name__})"
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if r.returncode != 0:
            tail = scrub((r.stderr or r.stdout or "")[-260:].replace("\n", " | "))
            return False, f"{t.name} رد شد: {tail}"
    return True, f"{len(ts)} تست سالم بود"


def _copy_tree(src, dst):
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.tmp*"))


def _apply_job(data):
    JOB.update(state="running", msg="شروع ...", steps=[], t=time.time())
    stage = None
    try:
        _step("بررسی فایل وصله ...")
        ins = inspect_patch(data)
        if not ins["ok"]:
            raise PatchError(" / ".join(ins["errors"]))
        man, files = _read_patch(data)
        pid = re.sub(r"[^A-Za-z0-9_\-]", "", str(man.get("id", "")))[:40] or secrets.token_hex(4)
        stage = E() / "stage" / pid
        shutil.rmtree(stage, ignore_errors=True)
        _step("ساخت کپی جدا برای آزمایش ...")
        _copy_tree(ROOT / "app", stage / "app")
        if (ROOT / "tests").is_dir():
            _copy_tree(ROOT / "tests", stage / "tests")
        for p, b in files.items():
            t = stage / p
            t.parent.mkdir(parents=True, exist_ok=True)
            t.write_bytes(b)
        ok, why = _gate(stage)  # بدون قفل: بقیه‌ی برنامه موقع تست‌ها منتظر نمی‌مونه
        if not ok:
            raise PatchError("تست رد شد، چیزی عوض نشد. " + why)
        _step("تست‌ها سالم بود؛ جایگزینی فایل‌ها ...")
        with _lock:
            ins = inspect_patch(data)  # دوباره: وسط تست‌ها فایل‌ها عوض نشده باشن
            if not ins["ok"]:
                raise PatchError("وسط کار فایل‌ها عوض شد: " + " / ".join(ins["errors"]))
            st = _load()
            entry = _promote(st, man, files, pid)
            enforce(st=st)
            _save(st)
        JOB.update(state="done", msg=f"نصب شد: «{entry['title']}». برنامه رو کامل ببند و دوباره باز کن.", need_restart=True)
    except PatchError as e:
        JOB.update(state="failed", msg=str(e))
    except Exception as e:
        JOB.update(state="failed", msg=f"خطای غیرمنتظره ({type(e).__name__}); چیزی عوض نشد.")
    finally:
        if stage:
            shutil.rmtree(stage, ignore_errors=True)


def apply_patch(data, wait=False):
    """نصب در پس‌زمینه (تست‌ها چند ثانیه طول می‌کشن). وضعیت از status() خونده می‌شه."""
    if JOB["state"] == "running":
        return False
    data = bytes(data)
    JOB.update(state="running", msg="شروع ...", steps=[], t=time.time(), need_restart=False)
    th = threading.Thread(target=_apply_job, args=(data,), daemon=True)
    th.start()
    if wait:
        th.join()
    return True


def _promote(st, man, files, pid):
    orig = E() / "original"
    if not orig.exists():  # عکس نسخه‌ی اصلی؛ همیشه می‌شه به این برگشت
        _copy_tree(ROOT / "app", orig / "app")
    vdir = E() / "versions" / pid
    shutil.rmtree(vdir, ignore_errors=True)
    rows = []
    for f in man["files"]:
        p, b = f["path"], files[f["path"]]
        ap = ROOT / p
        before = _fsha(ap)
        if ap.is_file():
            bk = vdir / "files" / p
            bk.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ap, bk)
        _atomic(ap, b)
        rows.append({"path": p, "action": f["action"], "before": before, "after": _sha(b)})
    entry = {"id": pid, "title": str(man.get("title", ""))[:120], "notes": str(man.get("notes", ""))[:600],
             "ts": int(time.time()), "files": rows, "active": True, "ok": False, "backup": True}
    st["applied"].append(entry)
    st["reports"].pop(str(man.get("report_id", "")), None)  # هر گزارش فقط یک بار وصله می‌گیره
    st["boot_tries"] = 0
    _log(st, f"وصله‌ی «{entry['title']}» نصب شد ({len(rows)} فایل).")
    return entry


# ------------------------------------------------------------ برگشت
def rollback(mode="last"):
    """mode='last': آخرین وصله؛ mode='original': همه‌چیز به نسخه‌ی اصلی. خروجی: (ok, پیام)."""
    with _lock:
        st = _load()
        act = [a for a in st["applied"] if a.get("active")]
        if not act:
            return False, "وصله‌ای نصب نیست."
        if mode == "original":
            orig = E() / "original" / "app"
            if not orig.is_dir():
                return False, "نسخه‌ی اصلی برای برگشت پیدا نشد."
            for a in act:
                for f in a["files"]:
                    if f["action"] == "add":
                        try:
                            (ROOT / f["path"]).unlink()
                        except OSError:
                            pass
            for p in orig.iterdir():
                if p.is_file():
                    shutil.copy2(p, ROOT / "app" / p.name)
            for a in act:
                a["active"] = False
            msg = "همه‌چیز به نسخه‌ی اصلی برگشت."
        else:
            a = act[-1]
            vdir = E() / "versions" / a["id"] / "files"
            for f in a["files"]:
                if f["action"] == "replace" and not (vdir / f["path"]).is_file():
                    return False, "پشتیبان این وصله پاک شده؛ فقط «برگشت به اصلی» ممکنه."
            for f in a["files"]:
                if f["action"] == "add":
                    try:
                        (ROOT / f["path"]).unlink()
                    except OSError:
                        pass
                else:
                    shutil.copy2(vdir / f["path"], ROOT / f["path"])
            a["active"] = False
            msg = f"وصله‌ی «{a.get('title', '')}» برداشته شد."
        st["boot_tries"] = 0
        _log(st, msg)
        _save(st)
        return True, msg


def early_guard(root, data=None):
    """اول cfgweb.py صدا زده می‌شه. اگه وصله‌ی تازه (هنوز تأییدنشده) سه بار پشت‌سرهم برنامه رو بالا نیاورد، خودش برمی‌گرده."""
    init(root, data or Path(root) / "data")
    if os.environ.get("CFG_NO_RESTART"):
        return
    with _lock:
        st = _load()
        pend = [a for a in st["applied"] if a.get("active") and not a.get("ok")]
        if not pend:
            return
        st["boot_tries"] = int(st.get("boot_tries", 0)) + 1
        _save(st)
        bad = st["boot_tries"] > 3
    if bad:
        ok, _ = rollback("last")
        if ok:
            import runpy
            runpy.run_path(str(Path(root) / "app" / "cfgweb.py"), run_name="__main__")  # با فایل‌های برگشته دوباره اجرا
            raise SystemExit(0)


def confirm_later(delay=25):
    """برنامه بعد از چند ثانیه سالم موندن، وصله رو تأیید می‌کنه (دیگه برگشت خودکار نداره؛ برگشت دستی هست)."""
    def run():
        time.sleep(delay)
        try:
            with _lock:
                st = _load()
                for a in st["applied"]:
                    if a.get("active"):
                        a["ok"] = True
                st["boot_tries"] = 0
                _save(st)
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


# ------------------------------------------------------------ سقف حجم
def enforce(st=None, cap_mb=None):
    """پوشه‌ی تکامل رو زیر سقف نگه می‌داره: اول پوشه‌های آزمایشی و پشتیبان‌های بیش از ۳ تا، بعد گزارش‌های قدیمی،
    بعد پشتیبان‌های قدیمی‌تر (همیشه آخری می‌مونه). «نسخه‌ی اصلی» و state هیچ‌وقت پاک نمی‌شن."""
    own = st is None
    acts = []
    with _lock:
        st = st or _load()
        cap = (cap_mb or st["cap_mb"]) * 1_000_000
        shutil.rmtree(E() / "stage", ignore_errors=True)

        def trim_backups(keep):
            vers = [a for a in st["applied"] if a.get("backup")]
            for a in vers[:max(0, len(vers) - keep)]:
                shutil.rmtree(E() / "versions" / a["id"], ignore_errors=True)
                a["backup"] = False
                acts.append("پشتیبان " + a["id"])

        def trim_reports(keep):
            rd = E() / "reports"
            fs = sorted(rd.iterdir(), key=lambda p: p.stat().st_mtime) if rd.is_dir() else []
            for p in fs[:max(0, len(fs) - keep)]:
                try:
                    p.unlink()
                    acts.append("گزارش " + p.name)
                except OSError:
                    pass

        trim_backups(KEEP)
        for rk, bk in ((3, KEEP), (1, 2), (0, 1)):
            if _dirsize(E()) <= cap:
                break
            trim_reports(rk)
            if _dirsize(E()) > cap:
                trim_backups(bk)
        if own:
            _save(st)
    return acts


def set_cap(mb):
    with _lock:
        st = _load()
        st["cap_mb"] = min(CAP_MAX, max(CAP_MIN, int(mb)))
        _save(st)
    return enforce()


def set_autotune(on):
    with _lock:
        st = _load()
        st["autotune"] = bool(on)
        _save(st)


def save_report_file(text):
    d = E() / "reports"
    d.mkdir(parents=True, exist_ok=True)
    name = "ConfigTool-report-%s.%s" % (time.strftime("%Y%m%d-%H%M%S"), "txt" if "CTREPORT-PLAIN1" in text[:400] else "ctreport")
    _atomic(d / name, text)
    return name


# ------------------------------------------------------------ تنظیم خودکار
def tune_note(tested, alive, first_secs):
    """بعد از هر جستجو: چند تا تست شد، چند تا سالم بود، و تا اولین سرور سالم چند ثانیه طول کشید (یا None)."""
    try:
        with _lock:
            st = _load()
            t = st["tune"]
            t["hist"] = (t["hist"] + [[int(time.time()), int(tested), int(alive),
                                       None if first_secs is None else round(float(first_secs), 1)]])[-12:]
            rec = [h for h in t["hist"][-4:] if h[1] >= 20]
            m, why = t["m"], t.get("why", "")
            if len(rec) >= 3:
                rate = sum(h[2] for h in rec) / max(1, sum(h[1] for h in rec))
                fs = [h[3] for h in rec if h[3] is not None]
                mean_first = sum(fs) / len(fs) if fs else None
                if rate < 0.03 or mean_first is None or mean_first > 80:
                    m, why = min(TUNE_MAX, m * 1.12), "پیدا کردن سرور سالم سخت یا کنده؛ تست هم‌زمان بیشتر شد"
                elif rate > 0.20 and mean_first < 25:
                    m, why = max(TUNE_MIN, m * 0.92), "سرور سالم زیاده و زود پیدا می‌شه؛ تست هم‌زمان کمتر شد (کم‌فشارتر)"
                else:
                    m, why = m + (1 - m) * 0.1, "وضعیت عادیه؛ به حالت پیش‌فرض نزدیک می‌شه"
            t["m"], t["why"] = round(m, 3), why
            _save(st)
    except Exception:
        pass


def tune_params(p):
    """تعداد تست زنده و نخ‌ها رو کم و زیاد می‌کنه؛ نرخ ارسال (rate) هیچ‌وقت عوض نمی‌شه چون انتخاب کاربره و چیزیه که اپراتور می‌بینه."""
    try:
        st = _load()
        if not st["autotune"]:
            return p
        m = st["tune"]["m"]
        q = dict(p)
        q["live"] = max(2, min(24, int(round(p["live"] * m))))
        q["workers"] = max(8, min(128, int(round(p["workers"] * m))))
        return q
    except Exception:
        return p


# ------------------------------------------------------------ وضعیت برای رابط
def status():
    st = _load()
    u = usage()
    return {"cap_mb": st["cap_mb"], "autotune": st["autotune"], "tune": {"m": st["tune"]["m"], "why": st["tune"].get("why", ""),
            "runs": len(st["tune"]["hist"])},
            "usage": {"code_kb": u["code"] // 1000, "code_max_kb": u["code_max"] // 1000, "evolve_kb": u["evolve"] // 1000,
                      "cap_kb": u["cap"] // 1000, "data_kb": u["data"] // 1000},
            "applied": [{"id": a["id"], "title": a.get("title", ""), "ts": a.get("ts", 0), "active": a.get("active", False),
                         "ok": a.get("ok", False), "backup": a.get("backup", False), "files": len(a.get("files", []))}
                        for a in st["applied"][-8:]],
            "log": st["log"][-8:], "job": {k: JOB.get(k) for k in ("state", "msg", "steps", "need_restart")}}


# ------------------------------------------------------------ ابزار خط فرمان (برای ساخت/خواندن فایل‌ها بیرون از برنامه)
def build_patch(root, edits, report_id, title, notes="", app_ver=""):
    """edits: {مسیر نسبی: بایت‌های فایل تازه}. فایل‌هایی که هست «جایگزینی» و بقیه «افزودن» حساب می‌شن."""
    root = Path(root)
    man = {"fmt": FMT, "id": "p" + secrets.token_hex(4), "title": title, "notes": notes, "report_id": report_id,
           "app_ver": app_ver, "created": time.strftime("%Y-%m-%d %H:%M:%S"), "base": {}, "files": []}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p, b in edits.items():
            cur = root / p
            if cur.is_file():
                man["base"][p] = _sha(cur.read_bytes())
            man["files"].append({"path": p, "action": "replace" if cur.is_file() else "add", "sha256": _sha(b), "size": len(b)})
            z.writestr("files/" + p, b)
        z.writestr("manifest.json", json.dumps(man, ensure_ascii=False, indent=1))
    return buf.getvalue()


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "decode":
        print(json.dumps(open_report(Path(sys.argv[2]).read_text(encoding="utf-8")), ensure_ascii=False, indent=1))
    else:
        print("usage: python evolve.py decode <file.ctreport>")
