#!/usr/bin/env python3
"""netprobe - سنجش سریع خودِ شبکه (نه سرورها)، قبل و هم‌زمان با جستجوی کانفیگ.
بر پایه‌ی FilterCheck؛ فقط کتابخانه‌ی استاندارد. چند ثانیه طول می‌کشه و فقط به زیرساخت بزرگ و خنثی (Cloudflare، Google، Quad9) وصل می‌شه.

اصل‌ها (برای اینکه هیچ‌وقت از «یک شکست» به «کل» نتیجه نگیریم):
  - هر نتیجه یکی از "yes" / "no" / "unknown" است. «no» فقط وقتی داده می‌شه که
      ۱) چند مقصد مستقل (حداقل ۳ مقصد زنده‌ی ثابت‌شده) همگی شکست خورده باشن،
      ۲) یک «کنترل» نشون بده خود اینترنت و همون مقصدها زنده‌ان (مثلاً پورت ۴۴۳ همون مقصدها باز شده)،
      ۳) برای فیلتر SNI: شکست روی همون IP که نام عادی ازش رد شده، دو بار پشت‌سرهم تأیید شده باشه.
  - مقصدی که خودش ثابت نکرده زنده است (۴۴۳ جواب نداده)، هیچ نتیجه‌ای برای «پورت‌های دیگه» نمی‌ده.
  - خروجی فقط برای «اولویت‌بندی» و (در یک مورد کاملاً ساختاری: UDP کاملاً مرده) حذف قطعی استفاده می‌شه."""
import os, random, socket, ssl, struct, threading, time
from concurrent.futures import ThreadPoolExecutor

# لنگرها: چند رنج مستقل Cloudflare (روی همه‌ی پورت‌های HTTPS/HTTP کلودفلر جواب می‌دن) + چند سرویس‌دهنده‌ی دیگه برای ۴۴۳.
CF_ANCHORS = ("104.16.132.229", "172.67.74.226", "188.114.97.3", "162.159.135.42", "141.101.115.10")
OTHER_ANCHORS = ("8.8.8.8", "9.9.9.9", "151.101.1.69")
PORTS = (443, 8443, 2053, 2083, 2087, 2096, 80, 8080, 8880)
NTP_IPS = ("162.159.200.1", "162.159.200.123", "216.239.35.0")
DNS_UDP = ("8.8.8.8", "1.1.1.1", "9.9.9.9")
NEUTRAL_SNI = "example.com"
FILTERED_SNI = ("instagram.com", "youtube.com", "telegram.org")
MIN_ANCHORS = 3  # حداقل مقصد زنده‌ی ثابت‌شده برای صدور «no»

_ERR = {"timeout": "timeout", "reset": "reset", "refused": "refused"}


def _close(*socks):
    for s in socks:
        try:
            if s is not None:
                s.close()
        except OSError:
            pass


# ------------------------------------------------------------------ ابزارهای پایه (در تست‌ها جایگزین می‌شن)
def tcp(ip, port, timeout=3.0):
    """زمان اتصال TCP به میلی‌ثانیه، یا None اگه نشد."""
    t0 = time.monotonic()
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
    except OSError:
        return None
    _close(s)
    return (time.monotonic() - t0) * 1000.0


def _hello(sni):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=sni)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return obj, inc, out, out.read()


def tls(ip, sni, port=443, timeout=4.0, frag=None):
    """دست‌دهی TLS با نام sni. True: سرور جواب داد (حتی با alert)؛ False: قطع/بی‌جواب (نشونه‌ی فیلتر)؛ None: خطای محلی.
    frag="xray": ClientHello مثل fragment خود xray (تکه‌های ۱۰۰ تا ۲۰۰ بایت با فاصله‌ی ۱۰ تا ۲۰ میلی‌ثانیه)."""
    try:
        obj, inc, out, hello = _hello(sni)
    except (ValueError, UnicodeError, ssl.SSLError):
        return None
    if not hello:
        return None
    pieces = [hello]
    if frag:
        pieces, i = [], 0
        while i < len(hello):
            n = random.randint(100, 200)
            pieces.append(hello[i:i + n])
            i += n
    sk = None
    try:
        sk = socket.create_connection((ip, port), timeout=timeout)
        sk.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for k, pc in enumerate(pieces):
            if k:
                time.sleep(random.uniform(0.010, 0.020))
            sk.sendall(pc)
        sk.settimeout(timeout)
        end = time.monotonic() + timeout
        while True:
            try:
                obj.do_handshake()
                return True
            except ssl.SSLWantReadError:
                pend = out.read()
                if pend:
                    sk.sendall(pend)
                data = sk.recv(16384)
                if not data:
                    return False
                inc.write(data)
            except ssl.SSLError:
                return True  # alert از طرف سرور = سرور جواب داد
            if time.monotonic() > end:
                return False
    except (socket.timeout, TimeoutError, ConnectionError):
        return False
    except ssl.SSLError:
        return True
    except OSError:
        return False
    finally:
        _close(sk)


def _dns_query(name, qid=0x1234, qtype=1):
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for lab in name.strip(".").split("."):
        q += bytes([len(lab)]) + lab.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(b, i):
    while i < len(b):
        n = b[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += n + 1
    return i


def _answers(b):
    """[(type, rdata)] از جواب DNS؛ [] اگه خراب بود."""
    out = []
    try:
        qd, an = struct.unpack(">HH", b[4:8])
        i = 12
        for _ in range(qd):
            i = _skip_name(b, i) + 4
        for _ in range(an):
            i = _skip_name(b, i)
            t, _, _, ln = struct.unpack(">HHIH", b[i:i + 10])
            out.append((t, b[i + 10:i + 10 + ln]))
            i += 10 + ln
    except (struct.error, IndexError):
        return []
    return out


def udp_dns(ip, timeout=2.5, name="example.com", qtype=1):
    """جواب‌های DNS روی UDP از resolver (لیست rdata)، یا None اگه بی‌جواب بود."""
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(timeout)
    try:
        sk.sendto(_dns_query(name, qtype=qtype), (ip, 53))
        data, _ = sk.recvfrom(2048)
    except OSError:
        return None
    finally:
        sk.close()
    return [r for t, r in _answers(data) if t == qtype] or ([] if len(data) > 12 else None)


def quic(ip, timeout=2.5):
    """بسته‌ی QUIC با نسخه‌ی ناشناخته؛ سرور QUIC لیست نسخه‌ها رو برمی‌گردونه (بدون رمزنگاری)."""
    pkt = bytes([0xC0]) + b"\x1a\x2a\x3a\x4a" + bytes([8]) + os.urandom(8) + bytes([8]) + os.urandom(8)
    pkt += b"\x00" * (1200 - len(pkt))
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(timeout)
    try:
        sk.sendto(pkt, (ip, 443))
        data, _ = sk.recvfrom(2048)
    except OSError:
        return False
    finally:
        sk.close()
    return len(data) >= 7 and bool(data[0] & 0x80) and data[1:5] == b"\0\0\0\0"


def ntp(ip, timeout=2.5):
    """زمان سرور NTP (ثانیه از 1970) یا None اگه جواب نداد. هم برای «UDP کار می‌کنه؟» و هم برای ساعت سیستم."""
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(timeout)
    try:
        sk.sendto(b"\x1b" + 47 * b"\0", (ip, 123))
        data, _ = sk.recvfrom(512)
    except OSError:
        return None
    finally:
        sk.close()
    if len(data) < 48:
        return None
    sec = struct.unpack(">I", data[40:44])[0]
    return float(sec - 2208988800) if sec > 2208988800 else None


def http_date(ip, timeout=4.0):
    """زمان سرور از هدر Date یک پاسخ HTTPS (وقتی UDP/NTP بسته است)؛ دقت چند ثانیه. None اگه نشد."""
    import email.utils
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    sk = ss = None
    try:
        sk = socket.create_connection((ip, 443), timeout=timeout)
        ss = ctx.wrap_socket(sk, server_hostname="one.one.one.one")
        ss.settimeout(timeout)
        ss.sendall(b"HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n")
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            ch = ss.recv(2048)
            if not ch:
                break
            buf += ch
    except (OSError, ssl.SSLError):
        return None
    finally:
        _close(ss, sk)
    for line in buf.split(b"\r\n"):
        if line[:5].lower() == b"date:":
            try:
                dt = email.utils.parsedate_to_datetime(line[5:].strip().decode("ascii", "ignore"))
                return dt.timestamp()
            except (TypeError, ValueError):
                return None
    return None


def asn_info(timeout=2.5):
    """ASN اپراتور (مثل 'AS44244') فقط با DNS (IP عمومی از OpenDNS، ASN از Team Cymru)، یا '' اگه نشد. IP ذخیره نمی‌شه."""
    try:
        r = udp_dns("208.67.222.222", timeout, "myip.opendns.com")
        if not r or len(r[0]) != 4:
            return ""
        ip = ".".join(str(x) for x in r[0])
        rev = ".".join(reversed(ip.split(".")))
        for res in ("1.1.1.1", "8.8.8.8"):
            t = udp_dns(res, timeout, rev + ".origin.asn.cymru.com", 16)
            if t and t[0]:
                txt = t[0][1:1 + t[0][0]].decode("ascii", "ignore")
                a = txt.split("|")[0].split()[0]
                if a.isdigit():
                    return "AS" + a
    except (OSError, IndexError, ValueError):
        pass
    return ""


# ------------------------------------------------------------------ سنجش و نتیجه‌گیری
def _pmap(fn, items, workers=16):
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items) or 1))) as ex:
        return list(ex.map(fn, items))


def probe(stop=lambda: False):
    """سنجش کامل (حدود ۳ تا ۸ ثانیه). نتیجه:
      net_ok: حداقل یک مقصد روی ۴۴۳ جواب داد؛ وگرنه هیچ نتیجه‌ی دیگری معتبر نیست
      ports: {پورت: yes|no|unknown}   udp / quic / sni_filtered / frag: yes|no|unknown
      rtt: {p50, p90, loss}   asn: 'AS…' یا ''   ev: شواهد خام (برای نمایش و تست)"""
    t0 = time.time()
    res = {"t": t0, "net_ok": False, "clock": None, "ports": {}, "udp": "unknown", "quic": "unknown", "sni_filtered": "unknown",
           "frag": "unknown", "rtt": {"p50": None, "p90": None, "loss": None}, "asn": "", "ev": {}}
    # --- مرحله‌ی A: کنترل (۴۴۳ روی همه‌ی لنگرها) + UDP عمومی + ASN، هم‌زمان
    anchors = list(CF_ANCHORS) + list(OTHER_ANCHORS)
    box = {}

    def job_asn():
        box["asn"] = asn_info()

    th = threading.Thread(target=job_asn, daemon=True)
    th.start()
    jobs = [("tcp", a) for a in anchors] + [("ntp", a) for a in NTP_IPS] + [("dns", a) for a in DNS_UDP]

    def runA(j):
        k, a = j
        if k == "tcp":
            return j, tcp(a, 443, 3.0)
        if k == "ntp":
            return j, ntp(a, 2.5)  # epoch یا None
        return j, udp_dns(a, 2.5) is not None
    ra = dict(_pmap(runA, jobs, 16))
    ms = {a: ra[("tcp", a)] for a in anchors}
    alive = [a for a in anchors if ms[a] is not None]
    alive_cf = [a for a in CF_ANCHORS if ms[a] is not None]
    lat = sorted(v for v in ms.values() if v is not None)
    res["net_ok"] = bool(alive)
    res["ev"]["anchors_alive"] = f"{len(alive)}/{len(anchors)}"
    if lat:
        res["rtt"] = {"p50": round(lat[len(lat) // 2], 1), "p90": round(lat[min(len(lat) - 1, int(len(lat) * 0.9))], 1),
                      "loss": round(1 - len(alive) / len(anchors), 2)}
    th.join(3.0)
    res["asn"] = box.get("asn", "")
    if not alive or stop():
        return res
    # UDP عمومی: «no» فقط وقتی هر ۶ آزمون (۳ NTP + ۳ DNS) بی‌جواب باشن و اینترنت (TCP) زنده باشه
    ntp_t = [ra[("ntp", a)] for a in NTP_IPS]
    udp_res = [t is not None for t in ntp_t] + [ra[("dns", a)] for a in DNS_UDP]
    res["udp"] = "yes" if any(udp_res) else ("no" if len(alive) >= MIN_ANCHORS else "unknown")
    res["ev"]["udp_ok"] = f"{sum(udp_res)}/{len(udp_res)}"
    # ساعت سیستم: اختلاف با زمان واقعی (NTP؛ اگه UDP بسته بود هدر Date از یک لنگر HTTPS)
    got = [t for t in ntp_t if t is not None]
    skew, src = None, ""
    if got:
        skew, src = sorted(t - time.time() for t in got)[len(got) // 2], "ntp"
    else:
        for a in alive_cf[:2]:
            d = http_date(a)
            if d is not None:
                skew, src = d - time.time(), "http"
                break
    if skew is not None:
        res["clock"] = {"skew": round(skew, 1), "src": src}
    # --- مرحله‌ی B: پورت‌ها، QUIC، SNI
    cf_ports = [p for p in PORTS if p != 443]
    jobsB = [("port", a, p) for p in cf_ports for a in alive_cf]
    jobsB += [("quic", a, 0) for a in alive_cf[:3]]
    sni_ips = alive_cf[:2]
    jobsB += [("sni", a, n) for a in sni_ips for n in (NEUTRAL_SNI,) + FILTERED_SNI]

    def runB(j):
        k, a, x = j
        if k == "port":
            return j, tcp(a, x, 3.0) is not None
        if k == "quic":
            return j, quic(a, 2.5)
        return j, tls(a, x, 443, 4.0)
    rb = dict(_pmap(runB, jobsB, 16)) if jobsB else {}
    for p in PORTS:
        if p == 443:
            res["ports"][443] = "yes"
            continue
        oks = [rb[("port", a, p)] for a in alive_cf]
        # «no» فقط با ≥۳ مقصد زنده‌ی ثابت‌شده (همه‌ی اون‌ها ۴۴۳ رو جواب دادن) که همگی این پورت رو ندادن
        res["ports"][p] = "yes" if any(oks) else ("no" if len(alive_cf) >= MIN_ANCHORS else "unknown")
    q = [rb[("quic", a, 0)] for a in alive_cf[:3]]
    if q:
        if any(q):
            res["quic"] = "yes"
        elif res["udp"] == "yes" and len(q) >= 2:
            res["quic"] = "no"        # UDP عمومی کار می‌کنه ولی QUIC روی ۴۴۳ نه (کنترل: UDP)
        elif res["udp"] == "no":
            res["quic"] = "no"        # کل UDP مرده
    # فیلتر SNI: روی همون IP نام عادی باز شده و نام فیلتری نه؛ دو بار تأیید
    bad_pairs = [(a, n) for a in sni_ips if rb.get(("sni", a, NEUTRAL_SNI)) is True for n in FILTERED_SNI
                 if rb.get(("sni", a, n)) is False]
    good_pairs = [(a, n) for a in sni_ips if rb.get(("sni", a, NEUTRAL_SNI)) is True for n in FILTERED_SNI
                  if rb.get(("sni", a, n)) is True]
    confirmed = []
    if bad_pairs and not stop():
        again = dict(_pmap(lambda p: (p, tls(p[0], p[1], 443, 4.0)), bad_pairs, 8))
        confirmed = [p for p, v in again.items() if v is False]
    res["ev"]["sni"] = f"neutral_ok={sum(1 for a in sni_ips if rb.get(('sni', a, NEUTRAL_SNI)) is True)} filtered_blocked={len(confirmed)} filtered_ok={len(good_pairs)}"
    if confirmed and len(confirmed) >= 2:
        res["sni_filtered"] = "yes"
    elif good_pairs and not bad_pairs:
        res["sni_filtered"] = "no"
    # --- مرحله‌ی C: اثر fragment (فقط اگه فیلتر SNI تأیید شد)
    if res["sni_filtered"] == "yes" and not stop():
        tests = []
        for a, n in confirmed[:4]:
            tests += [(a, n)] * 2  # هر کدوم دو بار
        out = _pmap(lambda p: tls(p[0], p[1], 443, 4.0, frag="xray"), tests, 8)
        ok = sum(1 for v in out if v is True)
        res["ev"]["frag"] = f"{ok}/{len(out)}"
        res["frag"] = "yes" if out and ok >= max(2, (len(out) + 1) // 2) else ("no" if out and ok == 0 else "unknown")
    elif res["sni_filtered"] == "no":
        res["frag"] = "unneeded"
    res["dur"] = round(time.time() - t0, 1)
    return res


# ------------------------------------------------------------------ تصمیم‌ها (فقط از نتیجه‌ی بالا)
UDP_PROTOS = ("hysteria2", "tuic")


def hard_skip(c, net):
    """حذف قطعی فقط با شواهد مستقیم برای «همین» پورت: پروتکل UDP روی ۴۴۳ وقتی QUIC و کل UDP (۹ آزمون مستقل) با کنترل TCP مرده‌اند.
    برای پورت‌های دیگه فقط اولویت (priority) کم می‌شه؛ چون بسته‌بودن UDP روی ۵۳/۱۲۳/۴۴۳ یعنی همه‌ی UDPها بسته نیست.
    (pipeline هم این حذف رو فقط در مرحله‌ی ۱ اعمال می‌کنه؛ مرحله‌های بعد همه‌چیز رو تست می‌کنن.)"""
    return bool(net and net.get("net_ok") and net.get("udp") == "no" and net.get("quic") == "no"
                and c.get("proto") in UDP_PROTOS and c.get("port") == 443)


def priority(c, net):
    """عدد کوچک‌تر = زودتر تست بشه. هیچ‌وقت حذف نمی‌کنه؛ فقط ترتیب. اگه شبکه معلوم نیست همه 0."""
    if not net or not net.get("net_ok"):
        return 0
    p = 0
    port = c.get("port")
    st = net["ports"].get(port)
    if st == "no":
        p += 2          # پورت روی همه‌ی مقصدهای زنده‌ی کلودفلر بسته بود؛ آخر صف (ولی حذف نشده)
    if c.get("proto") in UDP_PROTOS and (net.get("udp") == "no" or (net.get("quic") == "no" and port == 443)):
        p += 3          # UDP/QUIC بسته به نظر می‌رسه؛ آخر صف
    return p


def want_frag(c, net):
    """True: از همون اول با fragment تست کن (فیلتر SNI تأیید شده و fragment واقعاً رد می‌شه)؛ False: بدون؛ None: مثل قبل."""
    if not net or not net.get("net_ok") or c.get("security") not in ("tls", "reality"):
        return None
    if net.get("sni_filtered") == "yes" and net.get("frag") == "yes":
        return True
    if net.get("sni_filtered") == "no":
        return False
    return None


def timeout_scale(net):
    """تایم‌اوت‌ها با پینگ پایه‌ی همین شبکه بزرگ می‌شن (نت همراه پینگ و نوسان بالاتری داره)؛ هیچ‌وقت کوچک‌تر از پیش‌فرض نمی‌شه."""
    try:
        p90 = net["rtt"]["p90"]
        loss = net["rtt"]["loss"] or 0
    except (TypeError, KeyError):
        return 1.0
    if not p90:
        return 1.0
    return round(min(3.0, max(1.0, p90 / 150.0 + (0.5 if loss >= 0.4 else 0.0))), 2)


def summary_fa(net):
    """یک خط خوانا برای نمایش به کاربر."""
    if not net:
        return ""
    if not net.get("net_ok"):
        return "سنجش شبکه: هیچ مقصد خنثی‌ای باز نشد (اینترنت قطع یا خیلی محدود)؛ تصمیمی بر اساسش گرفته نمی‌شه."
    yn = {"yes": "باز", "no": "بسته", "unknown": "نامشخص", "unneeded": "لازم نیست"}
    op = [str(p) for p, v in net["ports"].items() if v == "yes"]
    cl = [str(p) for p, v in net["ports"].items() if v == "no"]
    s = [f"پورت باز: {'، '.join(op) or '—'}"]
    if cl:
        s.append(f"بسته: {'، '.join(cl)}")
    s += [f"UDP: {yn[net['udp']]}", f"QUIC: {yn[net['quic']]}",
          "فیلتر SNI: " + {"yes": "تأیید شد", "no": "دیده نشد", "unknown": "نامشخص"}[net["sni_filtered"]]]
    if net["sni_filtered"] == "yes":
        s.append("fragment: " + yn.get(net["frag"], "نامشخص"))
    if net["rtt"]["p50"]:
        s.append(f"پینگ پایه ≈ {int(net['rtt']['p50'])}ms")
    return ("سنجش شبکه" + (f" ({net['asn']})" if net.get("asn") else "") + ": " + " | ".join(s))


CLOCK_BAD_SECS = 90  # VMess ±۱۲۰ ثانیه تحمل داره، Reality/TLS هم با ساعت خیلی غلط خراب می‌شن


def clock_bad(net):
    """True فقط اگه ساعت سیستم با زمان واقعی بیشتر از ۹۰ ثانیه فرق داشته باشه (اندازه‌گیری‌شده، نه حدس)."""
    try:
        return abs(net["clock"]["skew"]) > CLOCK_BAD_SECS
    except (TypeError, KeyError):
        return False


def clock_msg_fa(net):
    sk = net["clock"]["skew"]
    m = abs(sk) / 60.0
    d = "جلوتر" if sk < 0 else "عقب‌تر"
    amt = f"{m:.0f} دقیقه" if m < 120 else f"{m / 60:.1f} ساعت" if m < 2880 else f"{m / 1440:.0f} روز"
    return (f"ساعت دستگاهت حدود {amt} {d} از زمان واقعیه. با ساعت غلط، اتصال امن (TLS، Reality، VMess) خراب می‌شه و شبیه فیلتر یا سرور خراب دیده می‌شه؛ "
            "فعلاً هیچ سروری به‌خاطرش بد حساب نمی‌شه. «تنظیم خودکار تاریخ و ساعت» رو روشن کن (ویندوز: Settings ← Time & language؛ اندروید: Date & time ← Automatic).")


def net_kind():
    """نوع/اثرانگشت «خود اتصال» (نه اپراتور): مودم/وای‌فای خونه، نت همراه، یا هات‌اسپات. هیچ ترافیکی نمی‌فرسته و اگه نشه تشخیص داد خالی برمی‌گردونه.
    ASN تنها کافی نیست: مودم و سیم‌کارت از یک اپراتور هم ممکنه باشن. پس نوع اتصال هم توی شناسه‌ی شبکه می‌ره."""
    kind = ""
    droid = os.environ.get("CFG_ANDROID") == "1"
    if droid:  # اندروید: از خود سیستم می‌پرسیم. شبکه‌ی VPN (تونل خودمون) رو نادیده می‌گیریم تا وصل یا قطع بودن تونل نوع شبکه رو عوض نکنه
        try:
            from com.chaquo.python import Python
            cm = Python.getPlatform().getApplication().getSystemService("connectivity")
            have = set()
            for n in cm.getAllNetworks():
                caps = cm.getNetworkCapabilities(n)
                if caps is None or caps.hasTransport(4) or not caps.hasCapability(12):  # VPN یا بدون اینترنت
                    continue
                if caps.hasTransport(1):
                    have.add("wifi")
                elif caps.hasTransport(0):
                    have.add("mob")
                elif caps.hasTransport(3):
                    have.add("eth")
            for k in ("eth", "wifi", "mob"):  # اندروید وقتی چند شبکه هست، همین ترتیب رو ترجیح می‌ده
                if k in have:
                    kind = k
                    break
        except Exception:
            kind = ""
    ip = ""
    try:  # آدرس محلی؛ بدون ارسال بسته (UDP connect فقط مسیر رو انتخاب می‌کنه)
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sk.settimeout(1)
        sk.connect(("203.0.113.1", 9))
        ip = sk.getsockname()[0]
        sk.close()
    except Exception:
        ip = ""
    lan = ""
    if ip and not ip.startswith(("127.", "0.")):
        o = ip.split(".")
        if len(o) == 4:
            if ip.startswith("192.168.") or ip.startswith("172.20.10."):
                lan = ".".join(o[:3])      # مودم/هات‌اسپات: زیرشبکه‌ی ثابت
            elif not droid and kind != "mob":
                lan = ".".join(o[:2])      # شبکه‌ی 10.x یا 172.16-31 روی ویندوز (مودم/سازمان). توی اندروید این آدرس‌ها می‌تونن آدرس تونل باشن؛ نادیده
            if not kind and not droid and (ip.startswith("100.") or ip.startswith("192.0.0.")):
                kind = "mob"               # CGNAT / CLAT معمولاً نت همراهه
    if kind == "mob":
        return "mob"                       # آدرس محلی نت همراه هر بار عوض می‌شه؛ توی شناسه نمیاد
    return (kind + ":" + lan) if (kind or lan) else ""
