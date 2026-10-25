"""cfgact - تشخیص «الان کاربر چی‌کار می‌کنه» برای حالت «فوق هوشمند».

ورودی‌ها (همه محلی و فقط در حافظه؛ چیزی روی دیسک نوشته نمی‌شه):
  • آمار ترافیک خروجیِ xray (دانلود/آپلود واقعی از داخل تونل) از API محلی خودش
  • لاگ دسترسی xray (مقصد هر اتصال: پروتکل، میزبان، پورت، و پورت مبدأ)
  • اسم برنامه‌ای که اتصال رو باز کرده (فقط ویندوز؛ از جدول اتصال‌های سیستم). اگه نشد، بدون اون هم کار می‌کنه.

خروجی: یکی از  idle | normal | interactive | download | upload | call | secure  با دلیل کوتاه.
هیچ تصمیم جابه‌جایی‌ای اینجا گرفته نمی‌شه؛ فقط تشخیص (سیاست‌ها در cfgweb هستن).
"""
import json
import os
import re
import subprocess
import threading
import time
from collections import deque

ACTS = ("idle", "normal", "interactive", "download", "upload", "call", "secure")
FA = {"idle": "بی‌کار", "normal": "عادی", "interactive": "گشت‌وگذار", "download": "دانلود حجیم",
      "upload": "آپلود حجیم", "call": "تماس / زنده", "secure": "کار حساس"}

# ── فهرست‌ها: عمداً کوتاه و عمومی؛ تشخیص «نزدیک‌ترین حدس»ه، نه قطعی ──────────────────────────
SENSITIVE_HOST = ("bank", "paypal", "stripe", "wallet", "binance", "coinbase", "kraken", "kucoin", "bybit", "okx.",
                  "metamask", "payment", "shaparak", "mellat", "parsian", "pasargad", "tejarat", "sadad", "saman",
                  "bsi.ir", "bmi.ir", "melli", "refah", "sepehr", "bitwarden", "1password", "lastpass", "keepass",
                  "gov.", ".gov", "tax.", "irs.", "owa.", "vpn.", "anydesk", "teamviewer")
SENSITIVE_PROC = ("keepass", "bitwarden", "1password", "lastpass", "metamask", "exodus", "electrum", "ledger", "trezor",
                  "anydesk", "teamviewer", "mstsc", "putty", "winscp", "filezilla", "remote", "veracrypt")
CALL_PROC = ("zoom", "teams", "skype", "discord", "whatsapp", "telegram", "signal", "webex", "viber", "slack", "meet",
             "line", "imo", "facetime", "jitsi", "clubhouse")
INTERACTIVE_HOST = ("instagram", "cdninstagram", "fbcdn", "facebook", "youtube", "googlevideo", "ytimg", "ggpht",
                    "tiktok", "twitter", "twimg", "x.com", "reddit", "netflix", "spotify", "twitch", "aparat",
                    "pinterest", "linkedin", "snapchat", "whatsapp.net", "t.me", "telegram.org")
NOT_CALL_UDP_PORTS = {53, 123, 443, 5353, 1900, 137, 138, 853}  # DNS/NTP/QUIC/mDNS؛ تماس نیستن (QUIC روی این شبکه‌ها معمولاً بسته‌ست)

# آستانه‌ها (کیلوبیت بر ثانیه)
UP_MIN, UP_RATIO = 220, 2.5      # آپلود حجیم: میانگین ۱۵ ثانیه ≥ ۲۲۰kbit/s و ≥ ۲٫۵ برابر دانلود
DN_MIN, DN_RATIO = 1200, 2.5     # دانلود حجیم
RT_MIN = 24                      # زنده/تماس: هر دو جهت دست‌کم ۲۴kbit/s (حدود ۳ کیلوبایت/ثانیه)

_ACC = re.compile(r"from (?:(?:tcp|udp):)?(?P<src>\[[0-9a-fA-F:]+\]|[0-9a-fA-F\.:]+?):(?P<sport>\d+) accepted "
                  r"(?P<dst>\S+) \[(?P<inb>[\w\-]+) *(?:->|>>) *(?P<out>[\w\-]+)\]")


def parse_access(line, now=None):
    """یک خط لاگ دسترسی xray ← دیکشنری یا None. (API داخلی و خطوط غیرمرتبط نادیده گرفته می‌شن.)"""
    m = _ACC.search(line or "")
    if not m:
        return None
    out, dst = m.group("out"), m.group("dst")
    if out == "api" or m.group("inb") == "api-in":
        return None
    proto, host, port = "tcp", "", 0
    try:
        if dst.startswith(("tcp:", "udp:")):
            proto, rest = dst[:3], dst[4:]
            host, _, p = rest.rpartition(":")
            port = int(p)
        elif dst.startswith(("http://", "https://")):
            sch, rest = dst.split("://", 1)
            hp = rest.split("/", 1)[0]
            host, _, p = hp.rpartition(":") if ":" in hp and not hp.endswith("]") else (hp, "", "")
            host = host or hp
            port = int(p) if p.isdigit() else (443 if sch == "https" else 80)
        else:
            return None
    except ValueError:
        return None
    return {"t": now if now is not None else time.time(), "proto": proto, "host": host.strip("[]").lower(),
            "port": port, "sport": int(m.group("sport")), "inb": m.group("inb")}


def parse_stats(text):
    """خروجی `xray api statsquery` ← (آپلود، دانلود) کل بایت‌های خروجی‌های proxy-*. مقدار صفر در JSON حذف می‌شه."""
    up = dn = 0
    try:
        j = json.loads(text)
        for s in j.get("stat") or []:
            n, v = str(s.get("name", "")), int(s.get("value") or 0)
            if not n.startswith("outbound>>>proxy-"):
                continue
            if n.endswith(">>>uplink"):
                up += v
            elif n.endswith(">>>downlink"):
                dn += v
    except (ValueError, TypeError, AttributeError):
        return None
    return up, dn


def query_stats(xray, port, timeout=2.5):
    """یک بار شمارنده‌های ترافیک رو از API محلی xray می‌خونه؛ نشد = None."""
    try:
        r = subprocess.run([xray, "api", "statsquery", f"--server=127.0.0.1:{int(port)}"], capture_output=True, timeout=timeout,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), cwd=os.path.dirname(xray) or None)
        if r.returncode != 0:
            return None
        return parse_stats(r.stdout.decode("utf-8", "replace"))
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


class Rates:
    """نرخ آپلود/دانلود (kbit/s) از روی نمونه‌های پشت‌سرهم شمارنده (شمارنده با ری‌استارت xray صفر می‌شه؛ کاهش = شروع دوباره)."""

    def __init__(self, keep=120):
        self.s = deque(maxlen=keep)  # (t, up_total, dn_total)

    def add(self, up, dn, t=None):
        t = time.time() if t is None else t
        if self.s and (up < self.s[-1][1] or dn < self.s[-1][2]):
            self.s.clear()
        self.s.append((t, up, dn))

    def avg(self, sec):
        """میانگین نرخ در `sec` ثانیه‌ی آخر: (up_kbit, dn_kbit)؛ داده‌ی کم = (0, 0)."""
        if len(self.s) < 2:
            return 0.0, 0.0
        t1, u1, d1 = self.s[-1]
        base = self.s[0]
        for x in self.s:
            if t1 - x[0] <= sec:
                base = x
                break
        dt = t1 - base[0]
        if dt < 1.0:
            return 0.0, 0.0
        return (u1 - base[1]) * 8 / 1000 / dt, (d1 - base[2]) * 8 / 1000 / dt


def _has(s, words):
    s = s or ""
    return any(w in s for w in words)


def classify(flows, rates, procs=None, now=None):
    """تشخیص خام از روی اتصال‌های ۱۵ ثانیه‌ی اخیر و نرخ‌ها ← (act, reason, detail).
    اولویت: تماس/زنده > کار حساس > آپلود/دانلود حجیم > گشت‌وگذار > عادی > بی‌کار.
    procs: {sport: اسم برنامه} (اختیاری)."""
    now = time.time() if now is None else now
    procs = procs or {}
    fl = [f for f in flows if now - f["t"] <= 15]
    up15, dn15 = rates.avg(15)
    up5, dn5 = rates.avg(6)
    names = {f["sport"]: procs.get(f["sport"], "") for f in fl}
    pset = {n for n in names.values() if n}
    detail = {"up_kbit": round(up15), "dn_kbit": round(dn15), "flows": len(fl), "procs": sorted(pset)[:4]}

    udp = [f for f in fl if f["proto"] == "udp" and f["port"] not in NOT_CALL_UDP_PORTS]
    rt_rate = up15 >= RT_MIN and dn15 >= RT_MIN and max(up15, dn15) < 1500
    if udp and (rt_rate or any(_has(names.get(f["sport"], ""), CALL_PROC) for f in udp)):
        return "call", "جریان زنده‌ی UDP" + (f" ({', '.join(sorted(pset)[:2])})" if pset else ""), detail
    if any(_has(f["host"], ("stun", "turn.", "meet.", "zoom.", "webrtc")) for f in fl) and rt_rate:
        return "call", "تماس تصویری/صوتی (میزبان تماس)", detail

    sens = [f for f in fl if _has(f["host"], SENSITIVE_HOST)]
    if sens or any(_has(n.lower(), SENSITIVE_PROC) for n in pset):
        return "secure", "اتصال حساس (بانک/پرداخت/رمز/کنترل از راه دور)", detail

    inter = [f for f in fl if _has(f["host"], INTERACTIVE_HOST)]
    heavy_up = up15 >= UP_MIN and up15 >= UP_RATIO * max(dn15, 1.0) and up5 >= UP_MIN * 0.5
    heavy_dn = dn15 >= DN_MIN and dn15 >= DN_RATIO * max(up15, 1.0) and dn5 >= DN_MIN * 0.5
    if heavy_up:
        return "upload", f"آپلود پیوسته (~{round(up15 / 8)} KB/s)", detail
    if heavy_dn and not (inter and len(inter) >= len(fl) / 2):  # ویدیو/شبکه‌ی اجتماعی پرحجم «گشت‌وگذار»ه نه دانلودِ فایل
        return "download", f"دانلود پیوسته (~{round(dn15 / 8)} KB/s)", detail
    if inter or heavy_dn:
        return "interactive", "گشت‌وگذار/ویدیو (تأخیر کم مهمه)", detail
    if fl or up15 + dn15 >= 16:
        return "normal", "استفاده‌ی عادی", detail
    return "idle", "بی‌کار", detail


class Tracker:
    """هیسترزیس: وضعیت پایدار و بدون پرش. ورود به یک وضعیت سریع (تماس/حساس) یا کمی دیرتر (حجیم/گشت)، خروج دیرتر،
    تا یک لحظه‌ی کوتاه شلوغی تصمیم‌ها رو عوض نکنه."""
    ENTER = {"call": 5, "secure": 3, "upload": 8, "download": 8, "interactive": 8, "normal": 4, "idle": 20}
    EXIT = {"call": 40, "secure": 45, "upload": 25, "download": 25, "interactive": 30, "normal": 10, "idle": 5}
    PRIO = {"call": 6, "secure": 5, "upload": 4, "download": 4, "interactive": 3, "normal": 2, "idle": 1}

    def __init__(self):
        self.act, self.since, self.cand, self.cand_t, self.reason, self.detail = "idle", time.time(), None, 0.0, "", {}
        self.last_raw_t = {}

    def update(self, raw, reason="", detail=None, now=None):
        now = time.time() if now is None else now
        self.last_raw_t[raw] = now
        self.detail = detail or self.detail
        if raw == self.act:
            self.cand, self.reason = None, reason or self.reason
            return self.act
        if self.PRIO[raw] > self.PRIO[self.act] or now - self.last_raw_t.get(self.act, 0) >= self.EXIT[self.act]:
            if self.cand != raw:
                self.cand, self.cand_t = raw, now
            if now - self.cand_t >= self.ENTER[raw]:
                self.act, self.since, self.cand, self.reason = raw, now, None, reason
        else:
            self.cand = None
        return self.act

    def info(self, now=None):
        now = time.time() if now is None else now
        return {"act": self.act, "fa": FA[self.act], "since": int(now - self.since), "reason": self.reason, **self.detail}


# ── نام برنامه‌ی صاحب اتصال (فقط ویندوز، بدون پیش‌نیاز؛ هر خطایی = بی‌صدا «نامعلوم») ───────────────
def _win_procs(ports):
    """{پورت مبدأ: نام exe} برای اتصال‌هایی که از برنامه‌های همین سیستم به پراکسی محلی باز شدن (TCP و UDP)."""
    import ctypes
    from ctypes import wintypes
    out = {}
    iph = ctypes.WinDLL("iphlpapi", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    want = set(ports)

    def table(fn, cls_id, row_fmt):
        size = wintypes.DWORD(0)
        fn(None, ctypes.byref(size), False, 2, cls_id, 0)
        buf = ctypes.create_string_buffer(size.value)
        if fn(buf, ctypes.byref(size), False, 2, cls_id, 0) != 0:
            return []
        n = ctypes.c_uint32.from_buffer(buf, 0).value
        sz = ctypes.sizeof(row_fmt)
        return [row_fmt.from_buffer_copy(buf, 4 + i * sz) for i in range(n)]

    class TcpRow(ctypes.Structure):
        _fields_ = [("state", ctypes.c_uint32), ("la", ctypes.c_uint32), ("lp", ctypes.c_uint32),
                    ("ra", ctypes.c_uint32), ("rp", ctypes.c_uint32), ("pid", ctypes.c_uint32)]

    class UdpRow(ctypes.Structure):
        _fields_ = [("la", ctypes.c_uint32), ("lp", ctypes.c_uint32), ("pid", ctypes.c_uint32)]

    def port_of(v):
        return ((v & 0xFF) << 8) | ((v >> 8) & 0xFF)

    pids = {}
    for r in table(iph.GetExtendedTcpTable, 5, TcpRow):  # TCP_TABLE_OWNER_PID_ALL
        if port_of(r.lp) in want:
            pids[port_of(r.lp)] = r.pid
    for r in table(iph.GetExtendedUdpTable, 1, UdpRow):  # UDP_TABLE_OWNER_PID
        if port_of(r.lp) in want:
            pids.setdefault(port_of(r.lp), r.pid)
    cache = {}
    for sp, pid in pids.items():
        if pid not in cache:
            name = ""
            h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if h:
                buf = ctypes.create_unicode_buffer(520)
                n = wintypes.DWORD(520)
                if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                    name = os.path.basename(buf.value).lower()
                k32.CloseHandle(h)
            cache[pid] = name
        out[sp] = cache[pid]
    return out


def proc_names(ports):
    if os.name != "nt" or not ports:
        return {}
    try:
        return _win_procs(ports)
    except Exception:
        return {}


class Sampler:
    """جمع‌کننده: خطوط لاگ xray رو می‌خونه، شمارنده‌ها رو نمونه می‌گیره و وضعیت پایدار رو نگه می‌داره."""

    def __init__(self):
        self.flows = deque(maxlen=3000)
        self.rates = Rates()
        self.tracker = Tracker()
        self.lock = threading.Lock()
        self.pcache = {}  # پورت مبدأ ← (نام، زمان)

    def reset(self):
        """قطع اتصال: وضعیت قبلی (مثلاً «تماس») نباید روی اتصال بعدی اثر بذاره."""
        with self.lock:
            self.flows.clear()
        self.rates = Rates()
        self.tracker = Tracker()
        self.pcache.clear()

    def feed_line(self, line):
        f = parse_access(line)
        if f:
            with self.lock:
                self.flows.append(f)

    def reader(self, stream, stop):
        """خروجی xray رو (حتماً باید تخلیه بشه تا xray گیر نکنه) تا آخر می‌خونه."""
        try:
            for raw in iter(stream.readline, b""):
                if stop():
                    break
                try:
                    self.feed_line(raw.decode("utf-8", "replace"))
                except Exception:
                    pass
        except (OSError, ValueError):
            pass

    def tick(self, totals, now=None):
        now = time.time() if now is None else now
        if totals:
            self.rates.add(totals[0], totals[1], now)
        with self.lock:
            fl = list(self.flows)
        recent = [f for f in fl if now - f["t"] <= 15]
        ports = {f["sport"] for f in recent}
        procs = {}
        if os.name == "nt" and ports:
            need = [p for p in ports if now - self.pcache.get(p, ("", 0))[1] > 60]
            if need:
                for p, n in proc_names(need).items():
                    self.pcache[p] = (n, now)
                for p in need:
                    self.pcache.setdefault(p, ("", now))
            procs = {p: self.pcache[p][0] for p in ports if p in self.pcache}
            for p in [p for p, (_, t) in self.pcache.items() if now - t > 300]:
                self.pcache.pop(p, None)
        raw, why, det = classify(fl, self.rates, procs, now)
        self.tracker.update(raw, why, det, now)
        return self.tracker.info(now)
