#!/usr/bin/env python3
"""cfgweb - هسته‌ی برنامه: سرور محلی + رابط وب (در پنجره‌ی مثل-اپ Edge/Chrome باز می‌شه).
خودش کانفیگ‌ها رو از منابع GitHub پیدا می‌کنه، تست می‌کنه، تنظیمات می‌سازه و وصل می‌شه."""
import atexit, queue, tempfile, http.server, json, os, random, secrets, shutil, socket, subprocess, sys, threading, time
import ipaddress, re, urllib.parse, urllib.request, webbrowser
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
DATA = Path(os.environ.get("CFG_DATA") or ROOT / "data")
sys.path.insert(0, str(HERE))
import cfgscan, cfgforge, report  # noqa: E402

ANDROID = cfgscan.ANDROID  # CFG_ANDROID=1 را فقط پوسته‌ی اندروید تنظیم می‌کند

SOCKS, HTTP, LOCK_PORT = 10808, 10809, 47831
PREV, SRC_DB = DATA / "prev_proxy.json", DATA / "sources.json"
S = dict(stage="idle", step=0, pct=0, msg="آماده‌ست", note="", log=[], connected=None, blocked=0, beat=time.time())
BG, ASKING, DIRECT, CLOSING = [ANDROID], [False], [""], [0.0]  # اندروید: بسته‌شدن صفحه برنامه را نمی‌بندد
VPN, VPN_WANT, _PORTS = [False], [True], [False]  # VPN: تونل فعاله؛ VPN_WANT: کاربر خواسته
RUN, CUM, STATS_FILE = report.new_stats(), report.new_stats(), DATA / "stats.json"
SETTINGS = DATA / "settings.json"
STOP, XRAY_PROC, WIN, PORT, TOKEN, _lock, PIPE = threading.Event(), None, None, 0, "", None, None


class Cancel(Exception):
    pass


def say(m):
    S["log"] = (S["log"] + [m])[-60:]


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
        pass


# ------------------------------------------------------------ دیتابیس منابع
def load_db():
    try:
        db = json.loads(SRC_DB.read_text(encoding="utf-8"))
    except Exception:
        db = {"sources": []}
    have, removed, changed = {s["url"] for s in db["sources"]}, set(db.get("removed", [])), False
    for u in cfgscan.DEFAULT_SOURCES:  # منبع‌های جدیدِ نسخه‌های تازه خودکار اضافه می‌شن (مگر اینکه خودت حذفشون کرده باشی)
        if u not in have and u not in removed:
            db["sources"].append({"url": u, "on": True, "got": 0, "alive": 0})
            changed = True
    if changed or not SRC_DB.exists():
        save_db(db)
    return db


def save_db(db):
    DATA.mkdir(parents=True, exist_ok=True)
    SRC_DB.write_text(json.dumps(db, ensure_ascii=False, indent=1), encoding="utf-8")


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
            pass
    Path(path).write_bytes(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


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


def load_settings():
    try:
        return json.loads(SETTINGS.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(j):
    cur = load_settings()
    if j.get("profile") in cfgforge.PROFILES:
        cur["profile"] = j["profile"]
    if j.get("mode") in ("stable", "fast", "off"):
        cur["mode"] = j["mode"]
    for k in ("quick", "sysproxy"):
        if isinstance(j.get(k), bool):
            cur[k] = j[k]
    if j.get("direct", "") in cfgforge.COUNTRY_DIRECT or j.get("direct") == "":
        cur["direct"] = j.get("direct", "")
    DATA.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps(cur), encoding="utf-8")








def load_block():
    """فهرست سیاه همراه برنامه + نسخه‌ی به‌روزشده‌ی پس‌زمینه (اگه باشه)."""
    b = cfgscan.Blocklist()
    for p in (HERE / "blocklist.txt", DATA / "blocklist.txt"):
        b.load(p)
    cfgscan.BLOCK = b


def update_block():
    """به‌روزرسانی روزانه‌ی آروم و بی‌صدا؛ جدا از کار کاربر، با تایم‌اوت، و در صورت خطا همون نسخه‌ی قبلی می‌مونه."""
    try:
        time.sleep(30)
        p = DATA / "blocklist.txt"
        if p.exists() and time.time() - p.stat().st_mtime < 86400:
            return
        texts = []
        for u in cfgscan.BLOCK_SOURCES:
            for m in cfgscan.mirror_urls(u):
                try:
                    op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    texts.append(op.open(urllib.request.Request(m, headers={"User-Agent": "Mozilla/5.0"}),
                                         timeout=20).read(8_000_000).decode("utf-8", "replace"))
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


def check(c, rounds=1, timeout=3, speed=False):
    """تست واقعی یه کانفیگ روی یه نمونه‌ی جدا از xray (روی یه کپی تا اصل خراب نشه)."""
    cc = dict(c)
    cc["flags"] = set(c["flags"])
    try:
        cfgscan.live(cc, find_xray(), rounds, timeout, speed)
    except Exception:
        cc["alive"] = False
    cc["verified_at"] = time.time()
    return cc


def check_many(cs, rounds=1, timeout=3, workers=8, speed=False):
    if not cs:
        return []
    with ThreadPoolExecutor(max_workers=min(workers, len(cs))) as ex:
        return list(ex.map(lambda c: check(c, rounds, timeout, speed), cs))


MODE = ["stable"]
CUR = ["balanced"]
ROUNDS = {"balanced": 3, "speed": 2, "stable": 5, "secure": 3}
STRICT_BAD = {"no_tls", "weak_cipher", "legacy_aid", "no_sni", "insecure_cert"}


def rk(c):
    """معیار انتخاب بهترین سرور؛ هر حالت یه معیار واقعاً متفاوت داره."""
    m = CUR[0]
    if m == "speed":
        return (-((c.get("kbps") or 0) // 250), cost(c))
    if m == "stable":
        return (-(c.get("success") or 0), (c.get("jitter") or 0) + 0.5 * (c.get("lat") or 99999))
    if m == "secure":
        return (0 if c["security"] == "reality" else 1, cost(c))
    return (cost(c), 0)


def cost(c):
    """زمان تخمینی کامل شدن یک صفحه‌ی ~۵۰۰ کیلوبایتی: پاسخ‌دهی + زمان انتقال. پینگ بالا با سرعت خوب می‌تونه از پینگ پایین با سرعت ضعیف بهتر باشه."""
    k = c.get("kbps")
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


def start_xray(sel, profile, plain=False):
    """xray رو با لیست سرورها (دوباره) بالا میاره؛ وقتی پورت جواب داد برمی‌گرده."""
    global XRAY_PROC
    if sel and sel[0]["proto"] in cfgscan.SB_PROTOS:
        return start_singbox(sel[:1])
    sel = [c for c in sel if c["proto"] not in cfgscan.SB_PROTOS] or sel
    xray = find_xray()
    cfg, sel = cfgforge.make_client(sel, profile, None, [], SOCKS, HTTP,
                                    probe_interval="3s" if len(sel) > 1 else "30s", strategy="leastPing", plain=plain,
                                    block_ads=True, direct_country=DIRECT[0])
    old, XRAY_PROC = XRAY_PROC, None
    if old:
        old.terminate()
        try:
            old.wait(2)
        except subprocess.TimeoutExpired:
            old.kill()
    ensure_ports()
    cfg["inbounds"][0]["port"], cfg["inbounds"][1]["port"] = SOCKS, HTTP
    XRAY_PROC = subprocess.Popen([xray, "run", "-c", "stdin:"], cwd=os.path.dirname(xray),
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
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
        if len(pool) == 1 and plain is False and profile in ("stream", "gaming", "download"):
            continue
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
    return dict(kbps=c.get("kbps"), host=c["host"][:24], proto=c["proto"], network=c["network"], security=c["security"],
                port=c["port"], ping=c.get("tcp_ms") or c.get("lat"),
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
            keep.append(r)
    POOL["standby"] = sorted(keep, key=eff)


def set_active(sel, ms=None):
    POOL["active"] = sel
    if S["connected"] and sel:
        S["connected"].update(n=len(sel), warn=describe(sel[0])["warn"],
                              best=f"{sel[0]['proto']} / {sel[0]['network']} / {sel[0]['security']} / پورت {sel[0]['port']}")
        if ms:
            S["connected"]["ms"] = ms


def failover(gen, profile, sysproxy, mode):
    """فقط وقتی واقعاً قطع/ضعیف شده: سرور جایگزین رو با تست دقیق (چند نمونه) انتخاب می‌کنه."""
    t0 = time.time()
    S["note"] = "اتصال قطع یا ضعیف شد؛ در حال انتخاب سرور جایگزین با تست دقیق ..."
    bad = POOL.setdefault("bad", {})
    for c in POOL["active"]:
        c["strikes"] = c.get("strikes", 0) + 1
        bad[(c["host"], c["port"])] = time.time() + 600  # تا ۱۰ دقیقه برنمی‌گرده سراغش
    rest = [c for c in POOL["standby"] if c.get("strikes", 0) < 2 and bad.get((c["host"], c["port"]), 0) < time.time()]
    fresh = time.time() - 90
    rest.sort(key=lambda c: (c.get("verified_at", 0) < fresh, -(c.get("success") or 0), eff(c)))
    tried = set()
    for _ in range(3):  # مسیر سریع: جایگزینی که همین چند ثانیه‌ی پیش کاملاً سالم بوده؛ سلامتش بعد از اتصال دوباره با ترافیک واقعی چک می‌شه
        if GEN[0] != gen or STOP.is_set():
            return
        fastc = sorted([c for c in rest if id(c) not in tried and c.get("verified_at", 0) > time.time() - 45
                        and (c.get("success") or 0) >= 0.99 and not danger(c)], key=rk)
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
            save_good(sel)
            S.update(msg="وصل شدی ✓", note=f"جابه‌جایی خودکار انجام شد ({time.time() - t0:.1f} ثانیه)")
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
        good = sorted([r for r in check_many(cand, 2, 3) if solid(r)], key=rk)  # فقط سرور کاملاً سالم قبول می‌شه
        if not good or GEN[0] != gen:
            continue
        sel = start_xray(good[:POOL_SIZE] if mode == "fast" else good[:1], profile)
        ms = probe_retry(3, 3)
        if ms:
            POOL["standby"] = [c for c in rest if id(c) not in tried] + [g for g in good if g not in sel]
            set_active(sel, ms)
            POOL["switches"] += 1
            save_good(sel)
            S.update(msg="وصل شدی ✓", note=f"جابه‌جایی خودکار انجام شد ({time.time() - t0:.1f} ثانیه)")
            return
        for g in good[:1]:
            bad[(g["host"], g["port"])] = time.time() + 600
    S["note"] = "سرور آماده‌ای نمونده؛ اسکن دوباره شروع شد ..."
    threading.Thread(target=pipeline, args=(profile, True, sysproxy, mode, True), daemon=True).start()


def upgrade_check(gen, profile, hist):
    """ارتقای نادر و محتاطانه: فقط اگه سرور فعلی مدت‌ها کنده و جایگزین پایدارِ واضحاً بهتری هست. با بازگشت خودکار."""
    ok = sorted(h for h in hist if h)
    if len(ok) < 10:
        return
    med = ok[len(ok) // 2]
    if med < 400:
        return  # اختلاف کوچیک ارزش جابه‌جایی نداره
    res = check_many(sorted(POOL["standby"], key=eff)[:4], 4, 4, 4)
    good = sorted([r for r in res if solid(r)], key=eff)
    if not good or eff(good[0]) > 0.6 * med or GEN[0] != gen or STOP.is_set():
        return
    prev = list(POOL["active"])
    sel = start_xray(good[:1], profile)
    ms = probe_retry(3, 3)
    if ms and ms < 0.8 * med:
        POOL["standby"] = [c for c in POOL["standby"] if c["raw"] != sel[0]["raw"]] + prev
        set_active(sel, ms)
        S["note"] = "به یه سرور پایدارتر ارتقا یافت."
    else:
        start_xray(prev, profile)  # بهتر نبود؛ برگرد


class Pace:
    """سقف نرخ اتصال‌های آزمایشی (در ثانیه)؛ شبکه و اپراتور رو اذیت نکنه و شبیه اسکن پورت نباشه."""

    def __init__(self, rate):
        self.iv, self.t, self.lock = 1.0 / rate, 0.0, threading.Lock()

    def wait(self):
        with self.lock:
            now = time.time()
            self.t = max(self.t, now) + self.iv
            w = self.t - self.iv - now
        if w > 0:
            time.sleep(w)


def refill(gen, profile, seen):
    """وقتی وصلی، آروم و پیوسته جایگزین‌های تازه و تست‌شده می‌سازه تا لیست آماده هیچ‌وقت خالی نشه."""
    last_fetch, P = time.time(), cfgforge.PROFILES[profile]
    while GEN[0] == gen and S["stage"] == "connected" and not STOP.is_set():
        time.sleep(40)
        if GEN[0] != gen or S["stage"] != "connected" or len(POOL["standby"]) >= 14:
            continue
        batch = [POOL["backlog"].pop(0) for _ in range(min(8, len(POOL["backlog"])))]
        if not batch:
            if time.time() - last_fetch < 300:
                continue
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
                    if c:
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
    hist, fails = deque(maxlen=45), 0
    t_switch = t_eval = t_ref = time.time()
    while GEN[0] == gen and S["stage"] == "connected":
        time.sleep(0.5 if (mode == "fast" or fails) else random.uniform(2.0, 4.0))  # سالم: کم‌تعداد و نامنظم؛ مشکوک: سریع‌تر
        if GEN[0] != gen or S["stage"] != "connected":
            return
        dead = XRAY_PROC is None or XRAY_PROC.poll() is not None
        ms = None
        if not dead:
            try:
                ms = probe(1.5)
            except Exception:
                ms = None
        hist.append(ms)
        if ms:
            fails = 0
            if S["connected"]:
                S["connected"]["ms"] = ms
        else:
            fails += 1
        if mode == "off":
            continue
        okr = [h for h in hist if h]
        soft = mode == "stable" and len(hist) >= 30 and time.time() - t_switch > 60 and len(okr) / len(hist) < 0.6
        if dead or fails >= 3 or soft:
            failover(gen, profile, sysproxy, mode)
            hist.clear()
            fails, t_switch = 0, time.time()
        elif time.time() - t_ref > 60:
            refresh_standby(gen)
            t_ref = time.time()
        elif mode == "stable" and time.time() - t_eval > 600 and time.time() - t_switch > 600:
            upgrade_check(gen, profile, hist)
            t_eval = time.time()


def pipeline(profile, quick, sysproxy, failover_on="stable", auto=False, level=1, cycle=0):
    mode = failover_on if failover_on in ("stable", "fast", "off") else ("stable" if failover_on else "off")
    failover_on = mode != "off"
    try:
        STOP.clear()
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
        tmo = [2.5, 5] if level == 1 else [4, 9]
        if level >= 2:
            hard_cap *= 2
        seen, cands, origin, fst = set(), [], {}, {"n": 0}
        q, sem, lock, pend, blk = queue.Queue(), threading.Semaphore(8), threading.Lock(), [0], [0]
        skip = {"unsupported": 0, "insecure": 0}
        pace = Pace(6 if level == 1 else 12)
        ex = ThreadPoolExecutor(max_workers=24)
        found, connected, fails, t0, t_first = [], [False], [0], time.time(), [None]
        fetch_done = threading.Event()

        def work(c):
            try:
                if STOP.is_set():
                    return
                pace.wait()
                cfgscan.reach(c, tmo[0])
                if "blocklisted" in c["flags"]:
                    blk[0] += 1
                    S["blocked"] = blk[0]
                if not c.get("reachable") or "private_addr" in c["flags"]:
                    c["tested"], c["alive"] = True, False
                    return
                with sem:
                    if STOP.is_set():
                        return
                    try:
                        cfgscan.live(c, xray, 1, tmo[1])
                    except Exception:
                        c["alive"] = False
                    if level >= 2 and not c.get("alive") and c["security"] in ("tls", "reality") and not STOP.is_set():
                        try_variants(c, xray, tmo[1])
                c["tested"] = True
            finally:
                q.put(c)

        def add(links, tag="net"):
            parsed = []
            for l in links:
                if l in seen:
                    continue
                seen.add(l)
                c = cfgscan.parse(l)
                if not c:
                    continue
                cfgscan.static(c)
                c["src"] = tag
                if "blocklisted" in c["flags"]:
                    blk[0] += 1
                    continue
                if "unsupported" in c["flags"]:
                    skip["unsupported"] += 1
                    continue
                if "insecure_cert" in c["flags"]:
                    skip["insecure"] += 1
                    continue
                if ("private_addr" in c["flags"] or danger(c)
                        or not usable(c, P["only_encrypted"])
                        or (P["only_encrypted"] and c["flags"] & STRICT_BAD)):
                    continue
                parsed.append(c)
            parsed.sort(key=lambda c: "no_tls" in c["flags"])
            for c in parsed:
                cands.append(c)
                with lock:
                    pend[0] += 1
                ex.submit(work, c)

        add(read_links(DATA / "custom.txt"), "custom")  # اولویت: دستی، سالم‌های قبلی، بسته‌ی همراه، بعد منابع
        add(read_links(DATA / "good.txt"), "good")
        add(read_links(HERE / "snapshot.txt"), "snap")

        def fetcher():
            try:
                links, stats = cfgscan.fetch_sources(urls, per_source=2500, log=say, origin=origin, stop=STOP.is_set,
                                                     proxy_port=HTTP if XRAY_PROC else None)
                for s in db["sources"]:
                    if s["url"] in stats:
                        s["got"], s["alive"] = stats[s["url"]]["got"], 0
                fst["n"] = len(links)
                random.shuffle(links)
                add(links[:9000], "net")
            except Exception:
                pass
            finally:
                fetch_done.set()

        threading.Thread(target=fetcher, daemon=True).start()
        S.update(step=2, pct=8)

        def try_connect():
            res = connect_ladder(sorted(found, key=ping_key)[:1], profile, 1)
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
            POOL.update(active=sel, standby=[], switches=0, real_ip=real)
            connected[0], t_first[0] = True, time.time()
            # از اینجا به بعد جستجوی پس‌زمینه آروم می‌شه تا به اتصال فعال فشار نیاره و نتیجه‌ی تست بقیه رو خراب نکنه
            threading.Thread(target=lambda: [sem.acquire() for _ in range(6)], daemon=True).start()
            save_good(sel)
            S.update(stage="connected", pct=100, msg="وصل شدی ✓", connected=dict(
                ip=ip, ms=ms, n=len(sel), warn=describe(sel[0])["warn"], leak=leak, real_ip=real,
                best=f"{sel[0]['proto']} / {sel[0]['network']} / {sel[0]['security']} / پورت {sel[0]['port']}",
                system=bool(sysproxy and os.name == "nt")),
                note="در حال یافتن سرورهای بیشتر برای جابه‌جایی خودکار ..." if failover_on else "")

        finished = 0
        while not STOP.is_set():
            try:
                c = q.get(timeout=0.4)
            except queue.Empty:
                if (fetch_done.is_set() and finished >= pend[0]) or time.time() - t0 > hard_cap:
                    break
                continue
            finished += 1
            S["blocked"] = blk[0]
            if c.get("alive") and not danger(c):
                found.append(c)
                if not connected[0] and fails[0] < 4:
                    S.update(step=4, msg="اولین سرور سالم پیدا شد؛ در حال اتصال ...")
                    try_connect()
                    if not connected[0] and S["stage"] == "running" and not STOP.is_set():
                        S.update(step=2, msg=f"ادامه‌ی جستجو ... ({len(found)} سرور سالم پیدا شده)")
            if not connected[0]:
                S["pct"] = min(70, 8 + int(62 * finished / max(1, pend[0])))
                if S["stage"] == "running" and S["step"] == 2:
                    S["msg"] = (f"تست از شبکه‌ی خودت: {finished} از {pend[0]} | سالم: {len(found)}"
                                + ("" if fetch_done.is_set() else " | منابع در حال دانلود ..."))
            elif S["stage"] == "connected" and failover_on:
                S["note"] = f"در حال یافتن سرورهای بیشتر ... ({len(found)} سرور سالم تا الان)"
            if len(found) >= target or (t_first[0] and time.time() - t_first[0] > up_cap):
                break
        ex.shutdown(wait=False, cancel_futures=True)
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
        for c in found:
            for s in db["sources"]:
                if c["raw"] in origin and s["url"] == origin[c["raw"]]:
                    s["alive"] += 1
        save_db(db)
        if (not connected[0] and not STOP.is_set() and cycle < 8
                and not (P["only_encrypted"] and fst["n"] and not tested)):
            nxt = 2 if level >= 3 else level + 1  # هیچ‌وقت تسلیم نمی‌شه: مرحله‌ی بعد، بعد از کمی صبر دوباره از مرحله‌ی ۲
            S.update(stage="running", step=2, pct=8, msg=f"وصل نشد؛ تلاش با روش‌های قوی‌تر (مرحله {nxt}) ...")
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
            raise RuntimeError(f"{len(found)} سرور سالم پیدا شد ولی اتصال نهایی برقرار نشد. دوباره امتحان کن.")
        # اولین سرورِ وصل‌شده فقط «موقتی»ه؛ همه‌ی سرورهای سالم با تست آروم و چندنمونه‌ای دوباره و منصفانه سنجیده می‌شن
        ranked = sorted(found, key=ping_key)
        cur = list(POOL["active"])
        if S["stage"] == "connected" and cur and not STOP.is_set():
            S["note"] = "در حال بررسی دقیق سرورها (بدون فشار به اتصال) ..."
            others = [c for c in ranked if c["raw"] != cur[0]["raw"]]
            top = others[:8] + random.sample(others[8:], min(4, len(others[8:]))) + [cur[0]]
            ver = check_many(top, ROUNDS.get(profile, 3), 5, 4, speed=True)
            if STOP.is_set():
                return
            okc = sorted([r for r in ver if solid(r, need_ok())], key=rk)
            curv = next((r for r in ver if r["raw"] == cur[0]["raw"]), None)
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
                if best and best["raw"] != cur[0]["raw"] and (not (curv and solid(curv, need_ok())) or (rk(best) < rk(curv) and cost(best) < 0.75 * cost(curv))):
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
        save_good(POOL["active"] + POOL["standby"])
        MODE[0] = mode
        FAILOVER.set() if failover_on else FAILOVER.clear()
        S["note"] = (f"{len(POOL['active'])} سرور فعال و {len(POOL['standby'])} جایگزین آماده‌ست." if failover_on else "")
        POOL["backlog"] = [c for c in cands if not c.get("tested")]
        threading.Thread(target=refill, args=(GEN[0], profile, seen), daemon=True).start()
        threading.Thread(target=supervisor, args=(GEN[0], profile, sysproxy, mode), daemon=True).start()
    except Cancel:
        disconnect(silent=True)
        S.update(stage="idle", step=0, pct=0, msg="لغو شد", note="")
    except Exception as e:
        disconnect(silent=True)
        S.update(stage="error", msg=str(e))


# ------------------------------------------------------------ سرور محلی
def state():
    d = dict(S)
    d["log"] = S["log"][-25:]
    d["sources"] = load_db()["sources"]
    d["win"] = os.name == "nt"
    d["android"], d["vpn"] = ANDROID, VPN[0]
    d["methods"] = report.table(RUN["methods"], 8)
    d["rsum"] = {k: RUN[k] for k in ("tested", "reach", "alive", "blocked")}
    d["rsum"]["runs_total"] = CUM["runs"]
    d["servers"] = [dict(describe(c), role="active") for c in POOL["active"]] + \
                   [dict(describe(c), role="standby") for c in POOL["standby"][:12]]
    d["switches"], d["failover"] = POOL["switches"], FAILOVER.is_set()
    d["mode"] = MODE[0]
    d["ports"] = [SOCKS, HTTP]
    d["profile"] = CUR[0]
    d["settings"] = load_settings()
    return d


def quit_app(uninstall=False):
    STOP.set()
    t0 = time.time()
    while S["stage"] == "running" and time.time() - t0 < 20:
        time.sleep(0.5)
    shutdown()
    if uninstall and os.name == "nt" and re.fullmatch(r"[\w\s:\\./()-]+", str(ROOT)):  # فقط مسیر امن؛ بدون shell
        subprocess.Popen(f'cmd /c ping 127.0.0.1 -n 6 >nul & rmdir /s /q "{ROOT}"',
                         creationflags=0x00000008 | 0x08000000)
    os._exit(0)


def shutdown():
    disconnect(silent=True)
    try:
        (DATA / "run.json").unlink()
    except OSError:
        pass
    if WIN and os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(WIN.pid), "/T", "/F"], capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


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
        return secrets.compare_digest(t, TOKEN)

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        q = urllib.parse.parse_qs(u.query)
        if not self.auth(q):
            return self.reply(403, b"", "text/plain")
        if u.path == "/":
            html = (HERE / "ui.html").read_text(encoding="utf-8").replace("__T__", TOKEN)
            return self.reply(200, html.encode(), "text/html; charset=utf-8")
        if u.path == "/api/state":
            S["beat"] = time.time()
            return self.reply(200, state())
        if u.path == "/report":
            hdr = ({"Content-Disposition": 'attachment; filename="network-report-%s.html"' % time.strftime("%Y%m%d-%H%M")}
                   if q.get("dl") else None)
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
            j = json.loads(self.rfile.read(min(n, 10000)) or b"{}")
            if not isinstance(j, dict):
                raise ValueError("not an object")
        except Exception:
            return self.reply(400, {"error": "bad"})
        p = u.path
        if p == "/api/start":
            global PIPE
            DIRECT[0] = j.get("direct") if j.get("direct") in cfgforge.COUNTRY_DIRECT else ""
            VPN_WANT[0] = bool(j.get("sysproxy", True))
            if PIPE and PIPE.is_alive():
                STOP.set()
                PIPE.join(8)
            prof = j.get("profile") if j.get("profile") in cfgforge.PROFILES else "balanced"
            PIPE = threading.Thread(target=pipeline, args=(prof, bool(j.get("quick", True)),
                                                           bool(j.get("sysproxy", True)),
                                                           j.get("mode") if j.get("mode") in ("stable", "fast", "off") else "stable"),
                                    daemon=True)
            PIPE.start()
        elif p == "/api/stop":
            STOP.set()
            if S["stage"] != "running":
                disconnect()
            else:
                S["msg"] = "در حال لغو ..."
        elif p == "/api/clean":
            disconnect(silent=True)
            RUN.clear()
            RUN.update(report.new_stats())
            CUM.clear()
            CUM.update(report.new_stats())
            for fn in ("good.txt", "custom.txt", "stats.json"):
                try:
                    (DATA / fn).unlink()
                except OSError:
                    pass
            S.update(stage="idle", step=0, pct=0, msg="نتایج پاک شد", connected=None, log=[])
        elif p == "/api/import":
            ls = cfgscan.extract_links(str(j.get("text", ""))[:2_000_000])
            ls = [l for l in dict.fromkeys(ls) if cfgscan.parse(l)]
            if ls:
                DATA.mkdir(parents=True, exist_ok=True)
                cp = DATA / "custom.txt"
                write_secret(cp, "\n".join(list(dict.fromkeys(ls + read_links(cp)))[:3000]) + "\n")
            return self.reply(200, {"ok": True, "added": len(ls)})
        elif p == "/api/closing":
            if time.time() - CLOSING[0] > 2:  # سیل درخواست، ده‌ها نخ نسازه
                CLOSING[0] = time.time()
                threading.Thread(target=closing_check, args=(time.time(),), daemon=True).start()
        elif p == "/api/settings":
            save_settings(j)
        elif p == "/api/hide":
            BG[0] = True
            close_window()
        elif p == "/api/quit":
            threading.Thread(target=quit_app, daemon=True).start()
        elif p == "/api/uninstall":
            threading.Thread(target=quit_app, args=(True,), daemon=True).start()
        return self.reply(200, {"ok": True})


def open_window(url):
    global WIN
    if ANDROID:  # رابط داخل خود برنامه (WebView) است؛ آدرس/توکن هم لاگ نمی‌شود
        return
    BG[0] = False
    if os.environ.get("NOWINDOW"):
        print(url, flush=True)
        return
    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        b = os.environ.get(env)
        for rel in ("Microsoft/Edge/Application/msedge.exe", "Google/Chrome/Application/chrome.exe"):
            if b and (Path(b) / rel).exists():
                WIN = subprocess.Popen([str(Path(b) / rel), f"--app={url}", f"--user-data-dir={DATA / 'browser'}",
                                        "--window-size=470,900", "--no-first-run", "--no-default-browser-check",
                                        "--disable-background-mode", "--disable-background-timer-throttling",
                                        "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows"])
                return
    webbrowser.open(url)


def ask_background():
    """پنجره بسته شده ولی اتصال یا جستجو فعاله: می‌پرسه در پس‌زمینه ادامه بده یا کامل ببنده."""
    if os.name != "nt":
        return False
    import ctypes
    msg = ("اتصال هنوز فعاله.\n\nمی‌خوای برنامه در پس‌زمینه به کارش ادامه بده؟\n\n"
           "بله = ادامه در پس‌زمینه (برای دیدن دوباره‌اش ConfigTool رو اجرا کن)\nخیر = بستن کامل و قطع اتصال")
    # YESNO | ICONQUESTION | SETFOREGROUND | TOPMOST | RTLREADING ؛ ۶ یعنی «بله»
    try:
        return ctypes.windll.user32.MessageBoxW(0, msg, "ابزار اتصال", 0x24 | 0x10000 | 0x40000 | 0x100000) == 6
    except Exception:
        return True  # اگه نتونست بپرسه، اتصال رو قطع نکنه


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
    if S["beat"] > t or BG[0] or ASKING[0]:
        return
    ASKING[0] = True
    try:
        on_window_closed()
    finally:
        ASKING[0] = False


def on_window_closed():
    if S["stage"] in ("connected", "running") and ask_background():
        BG[0] = True
        close_window()
    else:
        quit_app()


def watchdog():
    global XRAY_PROC
    t0 = time.time()
    while True:
        time.sleep(2)
        if XRAY_PROC and XRAY_PROC.poll() is not None and S["stage"] == "connected" and not FAILOVER.is_set():
            XRAY_PROC = None
            restore_proxy()
            S.update(stage="error", msg="هسته‌ی اتصال متوقف شد. دوباره دکمه‌ی اتصال رو بزن.", connected=None)
        if WIN is not None and time.time() - t0 > 8 and WIN.poll() is not None and not ASKING[0]:
            ASKING[0] = True  # پنجره بسته شد (نه اینکه مرورگر تایمرها رو کند کرده)
            try:
                on_window_closed()
            finally:
                ASKING[0] = False
        elif WIN is None and not BG[0] and time.time() - S["beat"] > 900:
            quit_app()


def main():
    global PORT, TOKEN, _lock
    DATA.mkdir(parents=True, exist_ok=True)
    try:  # xray یتیمِ دفعه‌ی قبل (اگه برنامه ناگهانی بسته شده) پورت رو اشغال نکنه
        pid = int((DATA / "xray.pid").read_text(encoding="utf-8").strip())
        if ANDROID and not any(k in Path(f"/proc/{pid}/cmdline").read_bytes() for k in (b"libxray", b"libsingbox")):
            raise OSError("not ours")  # شناسه‌ی فرایند عوض شده؛ چیز دیگه‌ای رو نکش
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, creationflags=0x08000000)
        else:
            os.kill(pid, 9)
        (DATA / "xray.pid").unlink()
    except Exception:
        pass
    CUM.update(report.load(STATS_FILE))
    load_block()
    restore_proxy()  # اگه دفعه‌ی قبل ناگهانی بسته شده بود، تنظیم قبلی پروکسی برمی‌گرده
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
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    PORT, TOKEN = srv.server_address[1], secrets.token_urlsafe(16)
    url = f"http://127.0.0.1:{PORT}/?t={TOKEN}"
    rj = DATA / "run.json"
    rj.write_text(json.dumps({"url": url}), encoding="utf-8")
    os.chmod(rj, 0o600)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=watchdog, daemon=True).start()
    atexit.register(shutdown)
    S["beat"] = time.time()
    threading.Thread(target=update_block, daemon=True).start()
    open_window(url)
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
