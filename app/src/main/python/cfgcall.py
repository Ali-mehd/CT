"""cfgcall - «حالت تماس»: اندازه‌گیری کیفیت واقعیِ UDP از داخل تونل و برآورد کیفیت تماس صوتی (واتساپ/تلگرام).

چرا UDP؟ تماس صوتی/تصویری هر دو برنامه روی UDP (STUN/SRTP) می‌چرخه؛ تست HTTP یا پینگ TCP چیزی از کیفیتش نمی‌گه.
اینجا یک «پرسش STUN» کوچک (۲۰ بایت) از راه SOCKS5 UDP ASSOCIATE تونل فرستاده می‌شه؛ جواب سرور STUN یعنی UDP واقعاً از تونل
رفته و برگشته. از زمان رفت‌وبرگشت چند نمونه، تأخیر، نوسان (jitter) و افت بسته در میاد و با مدل E (ITU-T G.107، ساده‌شده) به
یک امتیاز MOS تبدیل می‌شه. فقط کتابخانه‌ی استاندارد؛ هیچ آدرس یا شناسه‌ای ذخیره نمی‌شه.

محدودیت صادقانه: این اندازه‌گیریِ «کلاینت ← سرور پراکسی ← سرور STUN» است، نه تا طرف مقابل تماس. برآوردِ MOS تقریبیه
(مدل G.711 با پنهان‌سازی افت؛ Opus معمولاً کمی بهتره، پس محافظه‌کارانه‌ست)."""
import os
import select
import socket
import struct
import time

STUN_TARGETS = (("stun.cloudflare.com", 3478), ("stun.l.google.com", 19302))
_COOKIE = 0x2112A442


def stun_request():
    txn = os.urandom(12)
    return struct.pack(">HHI", 0x0001, 0, _COOKIE) + txn, txn


def stun_ok(data, txn):
    """جواب STUN موفق (Binding success) با همون شناسه‌ی تراکنش؟"""
    return (len(data) >= 20 and data[0:2] == b"\x01\x01" and struct.unpack(">I", data[4:8])[0] == _COOKIE
            and data[8:20] == txn)


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("closed")
        buf += chunk
    return buf


def _associate(port, timeout):
    """SOCKS5 UDP ASSOCIATE روی پورت محلیِ تونل؛ (سوکت کنترل TCP، آدرس رله). خطا: OSError."""
    t = socket.create_connection(("127.0.0.1", port), timeout)
    try:
        t.settimeout(timeout)
        t.sendall(b"\x05\x01\x00")
        if _recv_exact(t, 2) != b"\x05\x00":
            raise OSError("socks auth")
        t.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        head = _recv_exact(t, 4)
        if head[0] != 5 or head[1] != 0:
            raise OSError("udp associate refused")
        if head[3] == 1:
            addr = socket.inet_ntoa(_recv_exact(t, 4))
        elif head[3] == 4:
            _recv_exact(t, 16)
            addr = "127.0.0.1"
        elif head[3] == 3:
            addr = _recv_exact(t, _recv_exact(t, 1)[0]).decode("ascii", "ignore")
        else:
            raise OSError("bad atyp")
        rport = struct.unpack(">H", _recv_exact(t, 2))[0]
        if addr not in ("127.0.0.1", "::1"):  # رله‌ی تونل محلی همیشه loopback است؛ آدرس دیگه‌ای که جواب بده نباید بسته‌ی UDP بگیره
            addr = "127.0.0.1"
        return t, (addr, rport)
    except Exception:
        t.close()
        raise


def _wrap(host, port, payload):
    h = host.encode("ascii")
    return b"\x00\x00\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port) + payload


def _unwrap(data):
    """بدنه‌ی بسته‌ی UDP از هدر SOCKS5؛ None اگه خراب بود."""
    try:
        atyp = data[3]
        i = 4 + (4 if atyp == 1 else 16 if atyp == 4 else 1 + data[4])
        return data[i + 2:]
    except IndexError:
        return None


def measure(port, count=20, interval=0.05, wait=1.5, targets=STUN_TARGETS):
    """از تونل محلی (SOCKS5 روی port) به هر سرور STUN `count` پرسش می‌فرسته (به‌صورت یک‌درمیان). اگه یکی از سرورهای STUN روی
    شبکه‌ی تو بسته باشه، نباید «افت بسته» حساب بشه؛ پس فقط سرِی برگردونده می‌شه که بهترین جواب‌دهی رو داشته (بیشترین جواب،
    بعد کمترین RTT میانه). خروجی: [RTT میلی‌ثانیه یا None] یا None اگه UDP اصلاً برقرار نشد. زمان کل ≲ count*len(targets)*interval + wait + ~۳ ثانیه."""
    try:
        ctl, relay = _associate(port, 3.0)
    except OSError:
        return None
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        u.setblocking(False)
        nt = len(targets)
        total = count * nt
        sent, rtt = {}, [[None] * count for _ in range(nt)]
        t0 = time.monotonic()
        end = t0 + total * interval + wait
        i = 0
        while time.monotonic() < end:
            now = time.monotonic()
            if i < total and now >= t0 + i * interval:
                pkt, txn = stun_request()
                host, p = targets[i % nt]
                sent[txn] = (i // nt, i % nt, now)
                try:
                    u.sendto(_wrap(host, p, pkt), relay)
                except OSError:
                    pass
                i += 1
                continue
            nxt = (t0 + i * interval - now) if i < total else (end - now)
            r, _, _ = select.select([u], [], [], max(0.0, min(0.02, nxt)))
            while r:
                try:
                    data, _ = u.recvfrom(2048)
                except OSError:
                    break
                body = _unwrap(data)
                if body and len(body) >= 20 and body[8:20] in sent:
                    idx, ti, ts = sent[body[8:20]]
                    if stun_ok(body, body[8:20]) and rtt[ti][idx] is None:
                        rtt[ti][idx] = (time.monotonic() - ts) * 1000.0
                r, _, _ = select.select([u], [], [], 0)

        def rank(series):
            ok = sorted(x for x in series if x is not None)
            return (-len(ok), ok[len(ok) // 2] if ok else 1e9)
        return min(rtt, key=rank)
    finally:
        u.close()
        ctl.close()


def quality(rtts):
    """از فهرست RTTها (None = گم‌شده) آمار می‌سازه: udp_ok، افت٪، RTT میانه/p95، نوسان (میانگین اختلاف نمونه‌های پشت‌سرهم)."""
    if not rtts:
        return {"n": 0, "got": 0, "udp_ok": False, "loss": 100.0, "p50": None, "p95": None, "jitter": None}
    ok = [x for x in rtts if x is not None]
    n, got = len(rtts), len(ok)
    q = {"n": n, "got": got, "udp_ok": got > 0, "loss": round(100.0 * (n - got) / n, 1), "p50": None, "p95": None, "jitter": None}
    if ok:
        s = sorted(ok)
        q["p50"] = round(s[len(s) // 2], 1)
        q["p95"] = round(s[min(len(s) - 1, int(len(s) * 0.95))], 1)
        q["jitter"] = round(sum(abs(a - b) for a, b in zip(ok, ok[1:])) / (len(ok) - 1), 1) if len(ok) > 1 else 0.0
    return q


def mos(q):
    """برآورد MOS (۱ تا ۴٫۵) با مدل E ساده‌شده. تأخیر یک‌طرفه ≈ RTT/2 + ۲۰ms بسته‌بندی + بافر نوسان (۲×jitter)."""
    if not q.get("udp_ok") or q.get("p50") is None:
        return 1.0
    d = q["p50"] / 2.0 + 20.0 + 2.0 * (q.get("jitter") or 0.0)
    ppl = min(100.0, q["loss"])
    idd = 0.024 * d + (0.11 * (d - 177.3) if d > 177.3 else 0.0)
    ie = 95.0 * ppl / (ppl + 25.1)
    r = max(0.0, min(100.0, 93.2 - idd - ie))
    return round(1 + 0.035 * r + r * (r - 60) * (100 - r) * 7e-6, 2) if r > 0 else 1.0


GRADES = ("unusable", "poor", "fair", "good", "excellent")
GRADE_FA = {"excellent": "عالی", "good": "خوب", "fair": "قابل‌قبول", "poor": "ضعیف", "unusable": "نامناسب برای تماس"}


def grade(q):
    """(درجه، دلیل‌های فارسی). اگه UDP رد نشه یا افت/نوسان خیلی زیاد باشه، MOS هر چی باشه درجه سقف داره."""
    if not q.get("udp_ok"):
        return "unusable", ["UDP از این تونل رد نمی‌شه؛ تماس برقرار نمی‌شه یا قطع و وصل می‌شه."]
    m = mos(q)
    g = 4 if m >= 4.0 else 3 if m >= 3.6 else 2 if m >= 3.1 else 1 if m >= 2.6 else 0
    why = []
    if q["loss"] >= 15:
        g = min(g, 0)
    elif q["loss"] >= 8:
        g = min(g, 1)
    elif q["loss"] >= 3:
        g = min(g, 2)
    if q["loss"] >= 3:
        why.append(f"افت بسته {q['loss']:g}٪")
    if (q["jitter"] or 0) >= 80:
        g = min(g, 1)
    elif (q["jitter"] or 0) >= 40:
        g = min(g, 2)
    if (q["jitter"] or 0) >= 40:
        why.append(f"نوسان زیاد (≈{q['jitter']:g} ms)")
    if (q["p95"] or 0) >= 600:
        g = min(g, 1)
    if (q["p50"] or 0) >= 300:
        g = min(g, 2)
    if (q["p50"] or 0) >= 300:
        why.append(f"تأخیر زیاد (≈{q['p50']:g} ms)")
    return GRADES[g], why


def assess(rtts):
    """همه‌ی خروجی‌های لازم برای نمایش و رتبه‌بندی."""
    q = quality(rtts)
    g, why = grade(q)
    q.update(mos=mos(q), grade=g, grade_fa=GRADE_FA[g], why=why)
    return q


def call_ok(q, min_grade="fair"):
    """سرور برای تماس قابل‌قبوله؟ (UDP رد می‌شه و درجه حداقل min_grade)"""
    return bool(q) and q.get("udp_ok") and GRADES.index(q.get("grade", "unusable")) >= GRADES.index(min_grade)


def measure_via(port, count=20):
    """اندازه‌گیری + برآورد در یک قدم؛ هیچ‌وقت استثنا نمی‌ده (None = تست انجام نشد)."""
    try:
        r = measure(port, count=count)
    except Exception:
        return None
    return assess(r) if r is not None else assess([])
