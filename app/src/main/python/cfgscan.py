"""cfgscan - تجزیه‌ی لینک کانفیگ‌ها (vmess/vless/trojan/ss/hysteria2/tuic/anytls)، تست واقعی از شبکه‌ی خود کاربر،
فهرست سیاه IP و دریافت منابع. فقط کتابخانه‌ی استاندارد پایتون؛ برای تست زنده به xray و sing-box نیاز داره."""
import functools, base64, hashlib, html as _html, ipaddress, json, os, re, shutil, socket, ssl
import statistics, struct, subprocess, tempfile, time, urllib.error, urllib.parse, urllib.request
import http.client
import threading
from concurrent.futures import ThreadPoolExecutor

MAX_LINK = 4096
ANDROID = bool(os.environ.get("CFG_ANDROID"))  # روی اندروید: DNS داخلی هسته و محیط کامل برای پروسه‌ها


def android_dns(cfg, c=None):
    """Go روی اندروید resolv.conf نداره؛ پس DNS داخلی xray و freedom با UseIP."""
    if not ANDROID:
        return cfg
    cfg["dns"] = {"servers": ["1.1.1.1", "8.8.8.8"]}
    for ob in cfg.get("outbounds", []):
        if ob.get("protocol") == "freedom":
            ob.setdefault("settings", {})["domainStrategy"] = "UseIP"
        elif c is not None and not c.get("ip") and ob.get("tag") != "fragment":
            ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["domainStrategy"] = "UseIP"
    return cfg
MAX_SUB_BYTES = 5 * 1024 * 1024
LAT_URL = "https://www.gstatic.com/generate_204"
IP_URL = "https://api.ipify.org"
PLAIN_URL = "http://example.com/"
SPEED_URLS = ["https://speed.cloudflare.com/__down?bytes=500000", "https://proof.ovh.net/files/1Mb.dat",
              "https://www.gstatic.com/webp/gallery/1.jpg"]
COMMON_PORTS = {80, 443, 8080, 8443, 2053, 2083, 2087, 2096}
WEAK_SS = re.compile(r"(rc4|^table$|bf-cfb|cast5|des|-cfb$|-ctr$|^chacha20$|^salsa20$)", re.I)
HOST_OK = re.compile(r"^[A-Za-z0-9.\-:]{1,253}$")

# کلید: (توضیح، جریمه‌ی امتیاز، شدت)
FLAGS = {
    "private_addr": ("آدرس داخلی/لوپ‌بک؛ تست نشد", 100, "danger"),
    "insecure_cert": ("allowInsecure فعاله (تأیید گواهی خاموشه)", 50, "danger"),
    "tls_verify_fail": ("گواهی TLS مقصد از داخل تونل معتبر نبود (احتمال MITM)", 100, "danger"),
    "tamper": ("محتوای HTTP ساده دستکاری/تزریق شده", 100, "danger"),
    "no_tls": ("بدون TLS/Reality؛ متادیتا قابل مشاهده‌ست", 25, "warn"),
    "weak_cipher": ("رمز قدیمی/ضعیف shadowsocks", 30, "warn"),
    "legacy_aid": ("vmess با alterId>0 (قدیمی)", 10, "warn"),
    "no_sni": ("SNI خالی روی آدرس IP", 10, "warn"),
    "odd_port": ("پورت غیرمعمول (احتمال فیلتر بیشتر)", 5, "info"),
    "blocked_recently": ("قبلاً زنده بود و الان قطعه (احتمال مسدود شدن)", 30, "warn"),
    "unstable": ("نرخ موفقیت در اجراهای اخیر پایین بوده", 25, "warn"),
    "high_jitter": ("نوسان تأخیر زیاد", 15, "warn"),
    "blocklisted": ("آدرس سرور روی فهرست سیاه امنیتی شناخته‌شده‌ست؛ تست نشد", 100, "danger"),
    "unsupported": ("نوع/ترنسپورت پشتیبانی‌نشده در این ابزار", 0, "info"),
}


# ---------------------------------------------------------------- parsing
def b64d(s):
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "replace")


def clean(s, n=255):
    return re.sub(r"[\x00-\x1f\x7f]", "", str(s or ""))[:n]


NETS = ("tcp", "ws", "grpc", "httpupgrade", "xhttp", "splithttp")


def mk(**kw):
    d = dict(proto="", host="", port=0, id="", pw="", method="", aid=0, scy="auto",
             network="tcp", security="none", sni="", hosthdr="", path="", svc="",
             flow="", pbk="", sid="", fp="", alpn="", insecure=False, name="", plugin=False,
             mode="", extra="", frag=False, obfs="", obfspw="", cc="", urm="", hdr="", ech="", enc="")
    d.update(kw)
    return d


# هر چیزی که روی ساخت کانفیگ اتصال اثر داره؛ دو لینک با همین مقدارها یک سرور واقعی‌ان (اسم و ترتیب پارامترها فرق نمی‌کنه)
KEY_FIELDS = ("proto", "host", "port", "id", "pw", "method", "aid", "scy", "network", "security", "sni", "hosthdr", "path",
              "svc", "flow", "pbk", "sid", "fp", "alpn", "insecure", "mode", "extra", "obfs", "obfspw", "cc", "urm",
              "hdr", "ech", "enc")
_CI = {"host", "id", "sni", "hosthdr"}  # نام دامنه و UUID به حروف حساس نیستن (رمز و مسیر هستن)


def ckey(c):
    """کلید یکتای سرور برای حذف تکراری‌ها؛ فقط #remark یا ترتیب پارامترها فرق داشته باشه یعنی تکراریه."""
    return tuple(str(c[k]).lower() if k in _CI else c[k] for k in KEY_FIELDS)


def p_vmess(link):
    j = json.loads(b64d(link[8:]))
    return mk(proto="vmess", host=clean(j.get("add")), port=int(j.get("port")),
              id=clean(j.get("id")), aid=int(j.get("aid") or 0), scy=clean(j.get("scy") or "auto", 20),
              network=clean(j.get("net") or "tcp", 20).lower(),
              security="tls" if j.get("tls") == "tls" else "none",
              sni=clean(j.get("sni")), hosthdr=clean(j.get("host")), path=clean(j.get("path"), 512),
              svc=clean(j.get("path"), 128), fp=clean(j.get("fp"), 30), alpn=clean(j.get("alpn"), 60),
              hdr=clean(j.get("type"), 20).lower(),
              insecure=str(j.get("allowInsecure", "")).lower() in ("1", "true"), name=clean(j.get("ps"), 80))


def p_url(link, sch):
    u = urllib.parse.urlsplit(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    ident = urllib.parse.unquote(u.username or "")
    sec = clean(q.get("security") or ("tls" if sch == "trojan" else "none"), 20).lower()
    return mk(proto=sch, host=clean(u.hostname), port=u.port or 0,
              id=clean(ident) if sch == "vless" else "", pw=clean(ident) if sch == "trojan" else "",
              network=clean(q.get("type") or "tcp", 20).lower(), security=sec,
              sni=clean(q.get("sni") or q.get("peer")), hosthdr=clean(q.get("host")),
              path=clean(urllib.parse.unquote(q.get("path", "")), 512), svc=clean(q.get("serviceName"), 128),
              flow=clean(q.get("flow"), 40), mode=clean(q.get("mode"), 20), extra=clean(q.get("extra"), 2000), pbk=clean(q.get("pbk"), 100), sid=clean(q.get("sid"), 40),
              fp=clean(q.get("fp"), 30), alpn=clean(q.get("alpn"), 60),
              hdr=clean(q.get("headerType"), 20).lower(), ech=clean(q.get("ech") or q.get("echConfigList"), 2000),
              enc=clean(q.get("encryption"), 2000),
              insecure=q.get("allowInsecure", q.get("insecure", "")).lower() in ("1", "true"),
              name=clean(urllib.parse.unquote(u.fragment), 80))


def p_ss(link):
    body, name = link[5:], ""
    if "#" in body:
        body, name = body.split("#", 1)
    plugin = "?" in body
    body = body.split("?", 1)[0]
    if "@" in body:
        ui, hp = body.rsplit("@", 1)
        ui = urllib.parse.unquote(ui) if ":" in ui else b64d(ui)
    else:
        ui, hp = b64d(body).rsplit("@", 1)
    method, pw = ui.split(":", 1)
    host, port = hp.rsplit(":", 1)
    return mk(proto="ss", host=clean(host.strip("[]")), port=int(port), method=clean(method, 40).lower(),
              pw=clean(pw), security="none", plugin=plugin, name=clean(urllib.parse.unquote(name), 80))


SB_PROTOS = ("hysteria2", "tuic", "anytls")
SINGBOX = ""  # مسیر sing-box؛ cfgweb تنظیمش می‌کنه (بدونش این پروتکل‌ها پشتیبانی‌نشده حساب می‌شن)


def _q(link):
    u = urllib.parse.urlsplit(link)
    return u, {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}


def _port(u):
    """پورت اول آدرس. hysteria2 گاهی فهرست یا بازه می‌ده (host:443,5000-6000) و u.port روی اون خطا می‌ده."""
    try:
        return u.port
    except ValueError:
        tail = u.netloc.rsplit("@", 1)[-1].rpartition("]")[2]
        m = re.match(r"\d+", tail.partition(":")[2]) if ":" in tail else None
        return int(m.group()) if m else 0


def p_hy2(link):
    u, q = _q(link)
    pw = urllib.parse.unquote(u.username or "") + (":" + urllib.parse.unquote(u.password) if u.password else "")
    return mk(proto="hysteria2", host=clean(u.hostname), port=_port(u) or 443, pw=clean(pw), security="tls",
              network="quic", sni=clean(q.get("sni")), alpn=clean(q.get("alpn"), 40),
              insecure=q.get("insecure", "").lower() in ("1", "true"), obfs=clean(q.get("obfs"), 20),
              obfspw=clean(q.get("obfs-password"), 100), name=clean(urllib.parse.unquote(u.fragment), 80))


def p_tuic(link):
    u, q = _q(link)
    return mk(proto="tuic", host=clean(u.hostname), port=u.port or 443, id=clean(urllib.parse.unquote(u.username or "")),
              pw=clean(urllib.parse.unquote(u.password or "")), security="tls", network="quic",
              sni=clean(q.get("sni")), alpn=clean(q.get("alpn"), 40), cc=clean(q.get("congestion_control"), 20),
              urm=clean(q.get("udp_relay_mode"), 20),
              insecure=(q.get("allow_insecure") or q.get("insecure") or "").lower() in ("1", "true"),
              name=clean(urllib.parse.unquote(u.fragment), 80))


def p_anytls(link):
    u, q = _q(link)
    return mk(proto="anytls", host=clean(u.hostname), port=u.port or 443, pw=clean(urllib.parse.unquote(u.username or "")),
              security="tls", network="tcp", sni=clean(q.get("sni")),
              insecure=q.get("insecure", "").lower() in ("1", "true"), name=clean(urllib.parse.unquote(u.fragment), 80))


def parse(link):
    link = link.strip()
    if len(link) > MAX_LINK:
        return None
    try:
        sch = link.split("://", 1)[0].lower()
        c = (p_vmess(link) if sch == "vmess" else p_url(link, sch) if sch in ("vless", "trojan")
             else p_ss(link) if sch == "ss" else p_hy2(link) if sch in ("hysteria2", "hy2")
             else p_tuic(link) if sch == "tuic" else p_anytls(link) if sch == "anytls" else None)
    except Exception:
        return None
    if not c or not HOST_OK.match(c["host"]) or not (0 < c["port"] < 65536):
        return None
    c["raw"] = link
    return c


_LINK_RE = re.compile(r"(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic|anytls)://[^\s\"'<>]+")


def _links_in(t):
    return [x for x in _LINK_RE.findall(_html.unescape(t)) if len(x) <= MAX_LINK]  # سقف طول؛ unescape: صفحه‌هایی مثل t.me/s/کانال


def extract_links(text):
    """اول لینک‌های معمولی (متن یا صفحه‌ی HTML)؛ اگه نبود، شاید ساب‌اسکریپشنِ base64 باشه."""
    ls = _links_in(text)
    if ls:
        return ls
    try:
        return _links_in(b64d(text))
    except Exception:
        return []


def sub_urls(text, links=()):
    """آدرس‌های https توی متن (لینک ساب‌اسکریپشن یا کانال). آدرس‌هایی که داخل خود لینک کانفیگ‌هان (مثلاً توی remark) حساب نمی‌شن."""
    # یک بار و خطی؛ قبلاً برای هر لینک کل متن دوباره پیمایش می‌شد (۵۰ هزار لینک روی ۵ مگابایت = ۱۳۶ ثانیه)
    rest = _LINK_RE.sub(" ", _html.unescape(text)) if links else text
    found = (m.rstrip(".,;،") for m in re.findall(r"https://[^\s\"'<>]+", rest))
    return list(dict.fromkeys(u for u in found if public_url(u)))[:5]


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_SITELOCAL = ipaddress.ip_network("fec0::/10")
_TEREDO = ipaddress.ip_network("2001::/32")


def is_internal_ip(ip):
    """هر آدرسی که عمومی نیست: خصوصی، loopback، link-local، CGNAT (100.64/10؛ تیل‌اسکیل و متادیتای ابری علی‌بابا)،
    رزرو، multicast، IPv4-mapped و آدرس‌های NAT64/6to4 که IPv4 داخلی رو پنهان می‌کنن."""
    if ip.version == 6:
        if ip.ipv4_mapped:
            return is_internal_ip(ip.ipv4_mapped)
        if ip in _NAT64:
            return is_internal_ip(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
        if ip.sixtofour:
            return is_internal_ip(ip.sixtofour)
        if ip in _SITELOCAL or ip in _TEREDO:
            return True
    return (not ip.is_global) or ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local


@functools.lru_cache(maxsize=8192)
def public_url(u):
    """آدرس‌های داخلی (localhost، IP خصوصی، نام بدون نقطه) دریافت نمی‌شن. عمداً DNS حل نمی‌شه: DNS آلوده‌ی بعضی شبکه‌ها
    آدرس‌های مسدودشده رو به IP خصوصی می‌بره و فقط مسیرهای کمکی (آینه، IP ثابت) به جواب می‌رسن."""
    try:
        h = (urllib.parse.urlsplit(u).hostname or "").lower()
    except ValueError:
        return False
    h = h.rstrip(".")  # «127.0.0.1.» هم همان آدرسه
    if h and not h.isascii():  # دامنه‌ی یونیکد (IDN) رد نمی‌شه؛ به punycode تبدیل و همین‌جا بررسی می‌شه (①②⑦.0.0.1 هم به 127.0.0.1 تبدیل و رد می‌شه)
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            return False
    if not h or h == "localhost" or h.endswith((".local", ".localhost", ".internal", ".localdomain", ".lan", ".home.arpa")) or h == "localhost.localdomain":
        return False
    if is_ip(h):
        return not non_public(ipaddress.ip_address(h))
    if re.fullmatch(r"[0-9a-fx.]+", h) and re.search(r"\d", h):  # شکل‌های قدیمی IPv4: 127.1، 0177.0.0.1، 0x7f.1
        try:
            return not non_public(ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(h))))
        except (OSError, ValueError):
            pass  # IP نیست؛ دامنه‌ای مثل b2b.de یا 5c.cc که فقط از حروف a-f و رقم ساخته شده، دامنه‌ی معمولیه و رد نمی‌شه
    m = re.search(r"(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})\.(?:nip\.io|sslip\.io|xip\.io|localtest\.me|lvh\.me)$", h)
    if m:  # دامنه‌ای که IP توش جاسازی شده (127.0.0.1.nip.io)
        try:
            return not non_public(ipaddress.ip_address(".".join(m.groups())))
        except ValueError:
            return False
    if h.endswith((".localtest.me", ".lvh.me")) or h in ("localtest.me", "lvh.me"):
        return False
    return "." in h


def non_public(ip):
    """هر آدرسی که روی اینترنت عمومی نیست: خصوصی، loopback، link-local (مثل 169.254.169.254)، CGNAT (100.64/10)،
    رزرو/مستندات و multicast. قبلاً CGNAT و چند بازه‌ی دیگه رد می‌شدن چون is_private برشون نمی‌گیره."""
    return is_internal_ip(ip)  # علاوه بر موارد بالا: IPv4-mapped، NAT64، 6to4 و site-local که IPv4 یا آدرس داخلی رو پنهان می‌کنن


# ---------------------------------------------------------------- کانال و گروه‌های عمومی پیام‌رسان‌ها به‌عنوان منبع
CHANNEL_HOSTS = {"t.me": "tg", "telegram.me": "tg", "telegram.dog": "tg", "rubika.ir": "web", "splus.ir": "web",
                 "sapp.ir": "web", "eitaa.com": "web", "ble.ir": "web"}
FOLLOW_HOSTS = ("raw.githubusercontent.com", "gist.githubusercontent.com", "github.com", "gitlab.com", "pastebin.com",
                "rentry.co", "paste.rs")
CHAN_WHY = {"empty": "لینک خالیه.", "host": "فقط لینک تلگرام (t.me)، روبیکا (rubika.ir)، سروش (splus.ir / sapp.ir)، ایتا و بله پشتیبانی می‌شه.",
            "noname": "نام کانال یا گروه توی لینک نیست.", "badname": "نام کانال درست نیست.",
            "private": "این کانال/گروه خصوصیه (لینک دعوت) و بدون ورود با حساب خودت خونده نمی‌شه. پیام‌هاش رو کپی کن و توی کادر پایین paste کن."}


def normalize_channel(text):
    """لینک یا @نام کانال/گروه عمومی -> (آدرس قابل‌خوندن، نوع) یا (None، علت)."""
    t = (text or "").strip()
    if not t:
        return None, "empty"
    if re.fullmatch(r"@?[A-Za-z][A-Za-z0-9_]{3,63}", t):  # فقط نام (تلگرام)
        return f"https://t.me/s/{t.lstrip('@')}", "tg"
    if not re.match(r"^[a-z][a-z0-9+.-]*://", t, re.I):
        t = "https://" + t
    try:
        u = urllib.parse.urlsplit(t)
        host = (u.hostname or "").lower()
        u.port  # پورت نامعتبر ValueError می‌ده
    except ValueError:
        return None, "host"
    host = host[4:] if host.startswith("www.") else host
    if u.scheme.lower() not in ("http", "https") or host not in CHANNEL_HOSTS:
        return None, "host"
    parts = [p for p in urllib.parse.unquote(u.path).split("/") if p]
    if CHANNEL_HOSTS[host] == "tg":
        if parts and parts[0] == "s":
            parts = parts[1:]
        if not parts:
            return None, "noname"
        name = parts[0]
        if name.startswith("+") or name.lower() in ("joinchat", "c", "addstickers", "addtheme", "share", "proxy", "socks", "login", "boost"):
            return None, "private"
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{3,63}", name):
            return None, "badname"
        return f"https://t.me/s/{name}", "tg"
    if not parts:
        return None, "noname"
    if any(p.lower() in ("joing", "joinc", "joinchat", "invite") or p.startswith("+") for p in parts):
        return None, "private"
    if not all(re.fullmatch(r"[\w.@-]{1,80}", p) for p in parts):
        return None, "badname"
    return f"https://{host}/" + "/".join(parts), "web"


def is_channel_url(u):
    try:
        h = (urllib.parse.urlsplit(u).hostname or "").lower()
    except ValueError:
        return False
    return (h[4:] if h.startswith("www.") else h) in CHANNEL_HOSTS


def follow_candidates(text):
    """لینک‌های داخل پیام‌ها که احتمالاً فایل ساب‌اسکریپشن‌اند (فقط https و میزبان‌های شناخته‌شده؛ بدون دنبال‌کردن هر لینکی)."""
    out = []
    for m in re.findall(r'href="(https://[^"]+)"', text):
        u = _html.unescape(m)
        try:
            p = urllib.parse.urlsplit(u)
        except ValueError:
            continue
        h = (p.hostname or "").lower()
        if h in CHANNEL_HOSTS or h.endswith(".telegram.org") or h == "telegram.org":
            continue
        if (h in FOLLOW_HOSTS or "/sub" in p.path.lower()) and public_url(u):  # لینک داخل پیام (کنترل‌شده توسط صاحب کانال) نباید ما رو به localhost/شبکه‌ی داخلی بفرسته
            out.append(u)
    return list(dict.fromkeys(out))[:6]


def channel_links(url, get, max_pages=10, secs=25):
    """چند صفحه‌ی آخر کانال/گروه عمومی رو می‌خونه. get(آدرس) -> متن صفحه. (کانفیگ‌ها، لینک‌های ساب پیدا‌شده)"""
    t_end = time.time() + secs
    links, subs, seen, page = [], [], set(), url
    tg = "://t.me/s/" in url
    for i in range(max_pages if tg else 1):
        try:
            text = get(page)
        except Exception:
            if i == 0:
                raise
            break  # صفحه‌ی قدیمی‌تر نیومد؛ همونی که داریم بسه
        links += extract_links(text)
        subs += follow_candidates(text)
        if not tg:
            break
        ids = [int(x) for x in re.findall(r'data-post="[^"/]+/(\d+)"', text)]
        if not ids:
            break
        lo = min(ids)
        if lo <= 1 or lo in seen or time.time() > t_end:
            break
        seen.add(lo)
        page = f"{url}?before={lo}"
    return list(dict.fromkeys(links)), list(dict.fromkeys(subs))[:6]


# ---------------------------------------------------------------- static analysis
BLOCK_SOURCES = [
    "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
]


class Blocklist:
    """فهرست سیاه IP (فقط IPv4): آدرس‌های تکی + بازه‌ها؛ جستجوی سریع با bisect."""

    def __init__(self):
        self.ips, self.starts, self.ends = set(), [], []

    def load(self, path):
        nets = list(zip(self.starts, self.ends))
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError:
            return self
        for line in lines:
            t = line.split("#")[0].strip()
            if not t:
                continue
            try:
                if "/" in t:
                    n = ipaddress.ip_network(t, strict=False)
                    if n.version == 4:
                        nets.append((int(n.network_address), int(n.broadcast_address)))
                else:
                    a = ipaddress.ip_address(t)
                    if a.version == 4:
                        self.ips.add(int(a))
            except ValueError:
                pass
        nets.sort()
        merged = []
        for a, b in nets:
            if merged and a <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        self.starts, self.ends = [m[0] for m in merged], [m[1] for m in merged]
        return self

    def contains(self, ip):
        import bisect
        try:
            a = ipaddress.ip_address(str(ip).split("%")[0])
        except ValueError:
            return False
        if a.version != 4:
            return False
        n = int(a)
        if n in self.ips:
            return True
        i = bisect.bisect_right(self.starts, n) - 1
        return i >= 0 and n <= self.ends[i]


BLOCK = Blocklist()


def normalize_blocklist(ipsum_text, netset_text, min_count=3):
    out = []
    for line in ipsum_text.splitlines():
        p = line.split()
        if len(p) >= 2 and not line.startswith("#") and p[1].isdigit() and int(p[1]) >= min_count:
            out.append(p[0])
    for line in netset_text.splitlines():
        t = line.split("#")[0].strip()
        if t:
            out.append(t)
    return "# merged blocklist: ipsum (listed by >=%d lists) + firehol level1\n" % min_count + "\n".join(out) + "\n"


def is_ip(h):
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def static(c):
    f = set()
    if c["proto"] in SB_PROTOS:
        if not SINGBOX:
            f.add("unsupported")
    elif (c["network"] not in NETS or c["security"] not in ("none", "tls", "reality") or c["plugin"]
          or c["ech"]  # ECH توی build_xray پیاده نشده؛ بدونش تست بی‌معنیه
          or "downloadsettings" in c["extra"].lower()  # آدرس دومِ بررسی‌نشده؛ ایمن نیست
          or (c["network"] == "tcp" and c["hdr"] == "http")  # مبهم‌سازی HTTP روی TCP پیاده نشده
          or (c["proto"] == "vless" and c["enc"] not in ("", "none"))):  # رمزنگاری vless (مثل mlkem) پیاده نشده
        f.add("unsupported")
    if c["security"] == "none" and c["proto"] != "ss" and c["proto"] not in SB_PROTOS:
        f.add("no_tls")
    if c["insecure"]:
        f.add("insecure_cert")
    if c["proto"] == "ss" and WEAK_SS.search(c["method"]):
        f.add("weak_cipher")
    if c["proto"] == "vmess" and c["aid"] > 0:
        f.add("legacy_aid")
    if c["security"] == "tls" and not c["sni"] and is_ip(c["host"]):
        f.add("no_sni")
    if c["port"] not in COMMON_PORTS:
        f.add("odd_port")
    if is_ip(c["host"]) and BLOCK.contains(c["host"]):
        f.add("blocklisted")
    if is_ip(c["host"]):
        ip = ipaddress.ip_address(c["host"])
        if non_public(ip):
            f.add("private_addr")
    c["flags"] = f
    return c


def reach(c, timeout=4):
    """DNS + بررسی آدرس داخلی + TCP connect. هیچ داده‌ای ارسال نمی‌شه."""
    c["reachable"] = False
    try:
        infos = socket.getaddrinfo(c["host"], c["port"], type=socket.SOCK_STREAM)
    except OSError:
        return c
    ips = list(dict.fromkeys(i[4][0].split("%")[0] for i in infos))
    ips.sort(key=lambda a: ":" in a)  # IPv4 اول: روی خیلی از شبکه‌ها IPv6 کار نمی‌کنه و xray هم همون آی‌پی انتخاب‌شده رو می‌گیره
    good, why = [], None
    for a in ips:  # فقط IPهای بد کنار گذاشته می‌شن؛ دامنه‌ای که IPهای سالم هم داره رد نمی‌شه (قبلاً یک IP بد کل سرور رو می‌انداخت)
        ip = ipaddress.ip_address(a)
        if non_public(ip):
            why = why or "private_addr"
        elif BLOCK.contains(ip):  # قبل از هر اتصالی؛ آنتی‌ویروس هم همین آدرس‌ها رو می‌بنده
            why = "blocklisted"
        else:
            good.append(a)
    if not good:
        c["flags"].add(why or "private_addr")
        return c
    ips = good
    c["ip"] = ips[0]  # همین آی‌پیِ بررسی‌شده توی کانفیگ می‌ره (جلوگیری از DNS rebinding)
    if c["proto"] in ("hysteria2", "tuic"):  # UDP: با TCP نمی‌شه سنجید؛ تست واقعی خودش تصمیم می‌گیره
        c["reachable"], c["tcp_ms"] = True, None
        return c
    for a in ips:  # فقط به آی‌پی‌های همین بررسی وصل می‌شیم (قبلاً اسم دوباره resolve می‌شد و می‌تونست جواب دیگه‌ای بده)
        t0 = time.time()
        try:
            socket.create_connection((a, c["port"]), timeout=timeout).close()
            c["ip"], c["reachable"], c["tcp_ms"] = a, True, int((time.time() - t0) * 1000)
            break
        except OSError:
            continue
    return c


# ---------------------------------------------------------------- live test via xray
XHTTP_EXTRA_OK = {"headers", "xPaddingBytes", "noGRPCHeader", "noSSEHeader", "scMaxEachPostBytes", "scMinPostsIntervalMs",
                  "scMaxBufferedPosts", "scStreamUpServerSecs", "xmux", "uplinkHTTPMethod", "xPaddingKey", "xPaddingHeader",
                  "xPaddingPlacement", "xPaddingMethod", "sessionPlacement", "sessionKey", "seqPlacement", "seqKey",
                  "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize"}


def safe_extra(ex):
    """extra از لینک ناشناس می‌آد. فقط گزینه‌های تنظیمی ساده؛ downloadSettings (یک آدرس و پورت دلخواه که xray بهش وصل می‌شه،
    مثلاً 127.0.0.1 یا روتر) و هر چیز تو در تو دیگه حذف می‌شه."""
    out = {}
    for k, v in ex.items():
        if k not in XHTTP_EXTRA_OK:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, dict) and k in ("headers", "xmux"):
            out[k] = {a: b for a, b in v.items() if isinstance(a, str) and isinstance(b, (str, int, float, bool))}
    return out


def build_xray(c, port):
    if c["proto"] == "vmess":
        ob = {"protocol": "vmess", "settings": {"vnext": [{"address": c.get("ip") or c["host"], "port": c["port"], "users": [
            {"id": c["id"], "alterId": c["aid"], "security": c["scy"]}]}]}}
    elif c["proto"] == "vless":
        ob = {"protocol": "vless", "settings": {"vnext": [{"address": c.get("ip") or c["host"], "port": c["port"], "users": [
            {"id": c["id"], "encryption": "none", "flow": c["flow"]}]}]}}
    elif c["proto"] == "trojan":
        ob = {"protocol": "trojan", "settings": {"servers": [{"address": c.get("ip") or c["host"], "port": c["port"], "password": c["pw"]}]}}
    else:
        ob = {"protocol": "shadowsocks", "settings": {"servers": [{"address": c.get("ip") or c["host"], "port": c["port"],
                                                                    "method": c["method"], "password": c["pw"]}]}}
    if c["proto"] != "ss":
        st = {"network": c["network"], "security": c["security"]}
        sni = c["sni"] or c["hosthdr"] or c["host"]
        if c["security"] == "tls":
            tls = {"serverName": sni, "allowInsecure": False, "fingerprint": c["fp"] or "chrome"}
            if c["alpn"]:
                tls["alpn"] = c["alpn"].split(",")
            st["tlsSettings"] = tls
        elif c["security"] == "reality":
            st["realitySettings"] = {"serverName": sni, "fingerprint": c["fp"] or "chrome",
                                     "publicKey": c["pbk"], "shortId": c["sid"], "spiderX": ""}
        if c["network"] == "ws":
            st["wsSettings"] = {"path": c["path"] or "/", "headers": {"Host": c["hosthdr"] or sni}}
        elif c["network"] == "grpc":
            st["grpcSettings"] = {"serviceName": c["svc"]}
        elif c["network"] == "httpupgrade":
            st["httpupgradeSettings"] = {"path": c["path"] or "/", "host": c["hosthdr"] or sni}
        elif c["network"] in ("xhttp", "splithttp"):
            st["network"] = "xhttp"
            xs = {"path": c["path"] or "/", "host": c["hosthdr"] or sni, "mode": c["mode"] or "auto"}
            try:
                ex = json.loads(c["extra"]) if c["extra"] else None
                if isinstance(ex, dict):
                    ex = safe_extra(ex)
                    if ex:
                        xs["extra"] = ex
            except ValueError:
                pass
            st["xhttpSettings"] = xs
        elif c["network"] == "h2":
            st["httpSettings"] = {"path": c["path"] or "/", "host": [h for h in (c["hosthdr"] or sni,) if h]}
        if c.get("frag"):  # ترفند fragment فقط برای این کانفیگ (کمک به عبور از فیلتر SNI)
            st.setdefault("sockopt", {})["dialerProxy"] = "fragment"
        ob["streamSettings"] = st
    return android_dns({"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [ob] + ([{"tag": "fragment", "protocol": "freedom", "settings": {"fragment": {
                "packets": "tlshello", "length": "100-200", "interval": "10-20"}}}] if c.get("frag") else [])}, c)


def build_singbox(c, inbounds):
    tls = {"enabled": True, "server_name": c["sni"] or c["host"], "insecure": bool(c.get("_test_insecure"))}
    if c["alpn"]:
        tls["alpn"] = c["alpn"].split(",")
    elif c["proto"] in ("hysteria2", "tuic"):
        tls["alpn"] = ["h3"]
    base = {"tag": "proxy", "server": c.get("ip") or c["host"], "server_port": c["port"], "tls": tls}
    if c["proto"] == "hysteria2":
        ob = dict(base, type="hysteria2", password=c["pw"])
        if c["obfs"]:
            ob["obfs"] = {"type": c["obfs"], "password": c["obfspw"]}
    elif c["proto"] == "tuic":
        ob = dict(base, type="tuic", uuid=c["id"], password=c["pw"], congestion_control=c["cc"] or "bbr",
                  udp_relay_mode=c["urm"] or "native")
    else:
        ob = dict(base, type="anytls", password=c["pw"])
    return {"log": {"level": "error"}, "dns": {"servers": [({"type": "udp", "tag": "l", "server": "1.1.1.1"} if ANDROID else {"type": "local", "tag": "l"})]}, "inbounds": inbounds,
            "outbounds": [ob, {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy", "default_domain_resolver": "l"}}


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def recvn(s, n):
    b = b""
    while len(b) < n:
        x = s.recv(n - len(b))
        if not x:
            raise ConnectionError("closed")
        b += x
    return b


def fetch(port, url, timeout, limit=65536):
    """GET از طریق SOCKS5 محلی. دامنه رو خودِ سرور resolve می‌کنه (بدون نشت DNS محلی)."""
    u = urllib.parse.urlsplit(url)
    host, https = u.hostname, u.scheme == "https"
    dport = u.port or (443 if https else 80)
    t0 = time.time()
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00":
            raise ConnectionError("socks")
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dport))
        r = recvn(s, 4)
        if r[1] != 0:
            raise ConnectionError("connect")
        if r[3] == 1:
            recvn(s, 6)
        elif r[3] == 4:
            recvn(s, 18)
        else:
            recvn(s, recvn(s, 1)[0] + 2)
        if https:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        path = (u.path or "/") + ("?" + u.query if u.query else "")
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
                  f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n".encode())
        data = b""
        deadline = t0 + timeout * 2 + 5  # سقف کل زمان (سرور دشمن نتونه قطره‌قطره داده بده و گیر بندازه)
        try:
            while len(data) < limit and time.time() < deadline:
                x = s.recv(8192)
                if not x:
                    break
                data += x
        except (ssl.SSLError, OSError):
            if not data:
                raise
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():  # HTTP/1.1 ممکنه chunked جواب بده
        out, rest = b"", body
        while rest:
            size, _, rest = rest.partition(b"\r\n")
            try:
                n = int(size.split(b";")[0], 16)
            except ValueError:
                break
            if n <= 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        body = out
    try:
        status = int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        raise ConnectionError("bad http response")
    return status, body, int((time.time() - t0) * 1000)


SPEED_BIG_URLS = ["https://speed.cloudflare.com/__down?bytes=20000000", "https://proof.ovh.net/files/10Mb.dat",
                  "https://cachefly.cachefly.net/10mb.test"]


def _stream(port, url, secs, res, i, timeout):
    """یک دانلود از طریق SOCKS؛ نرخ فقط از اولین بایتِ بدنه حساب می‌شه (بدون هزینه‌ی اتصال و دست‌دهی TLS)."""
    try:
        u = urllib.parse.urlsplit(url)
        host, https = u.hostname, u.scheme == "https"
        dport = u.port or (443 if https else 80)
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            s.settimeout(timeout)
            s.sendall(b"\x05\x01\x00")
            if recvn(s, 2) != b"\x05\x00":
                raise ConnectionError("socks")
            h = host.encode()
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", dport))
            r = recvn(s, 4)
            if r[1] != 0:
                raise ConnectionError("connect")
            recvn(s, 6) if r[3] == 1 else recvn(s, 18) if r[3] == 4 else recvn(s, recvn(s, 1)[0] + 2)
            if https:
                s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            path = (u.path or "/") + ("?" + u.query if u.query else "")
            s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
                      f"Accept-Encoding: identity\r\nConnection: close\r\n\r\n".encode())
            buf, t_hdr = b"", time.time() + timeout * 2
            while b"\r\n\r\n" not in buf and len(buf) < 16384 and time.time() < t_hdr:  # سرورِ قطره‌چکان نتونه نخ رو برای همیشه نگه داره
                x = s.recv(8192)
                if not x:
                    return
                buf += x
            head, _, body = buf.partition(b"\r\n\r\n")
            if b" 200" not in head.split(b"\r\n")[0]:
                return
            t_first = time.time()
            n, end = len(body), t_first + secs
            while time.time() < end:
                x = s.recv(65536)
                if not x:
                    break
                n += len(x)
            res[i] = (n, time.time() - t_first)
        finally:
            s.close()
    except Exception:
        pass


def measure_kbps(port, secs=3.0, streams=2, timeout=6, urls=None):
    """سرعت واقعی دانلود از داخل تونل (کیلوبیت بر ثانیه)؛ چند اتصال هم‌زمان، نرخ بعد از شروع انتقال."""
    import threading
    for url in (urls or SPEED_BIG_URLS):
        res = [None] * streams
        ths = [threading.Thread(target=_stream, args=(port, url, secs, res, i, timeout), daemon=True) for i in range(streams)]
        for t in ths:
            t.start()
        for t in ths:
            t.join(secs + timeout + 2)
        got = [r for r in res if r]
        total, dt = sum(n for n, _ in got), max((d for _, d in got), default=0)
        if total > 100_000 and dt > 0.4:
            return int(total * 8 / 1000 / dt)
    return None


SITES = {"yt": "https://www.youtube.com/generate_204", "ig": "https://www.instagram.com/robots.txt"}
TG_DCS = (("149.154.167.51", 443), ("149.154.167.91", 443), ("149.154.175.53", 443))  # سرورهای واقعی خود تلگرام (اپ تلگرام به اینا وصل می‌شه، نه به telegram.org)


def tcp_via(port, ip, dport, timeout=5):
    """از داخل تونل فقط یه اتصال TCP به IP مشخص می‌سازه (هیچ داده‌ای نمی‌فرسته)."""
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if recvn(s, 2) != b"\x05\x00":
            return False
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack(">H", dport))
        return recvn(s, 4)[1] == 0
    except Exception:
        return False
    finally:
        s.close()


def site_check(port, timeout=5):
    """از داخل تونل: یوتیوب، اینستاگرام و تلگرام واقعاً می‌رسن؟
    یوتیوب و اینستاگرام: هر پاسخ HTTP یعنی رسیده (فقط خطای شبکه و ۵xx یعنی نه). تلگرام: اتصال به سرورهای خود تلگرام باز بشه.
    هر تست اگه بار اول شکست خورد یک بار دیگه با زمان بیشتر امتحان می‌شه تا کندیِ لحظه‌ای به‌حساب بسته‌بودن نیاد."""
    res = {}

    def http_ok(url):
        for t in (timeout, timeout + 3):
            try:
                st, _, _ = fetch(port, url, t)
                if st < 500 and st not in (403, 429):  # ۴۰۳/۴۲۹ یعنی گوگل/اینستاگرام این آی‌پی رو بسته یا محدود کرده؛ قبلاً «باز» حساب می‌شد
                    return True
            except Exception:
                pass
            time.sleep(0.4)
        return False

    def tg_ok():
        for t in (timeout, timeout + 3):
            for ip, dp in TG_DCS:
                try:
                    if tcp_via(port, ip, dp, t):
                        return True
                except Exception:
                    pass
        return False

    def one(k, fn, *a):
        try:
            res[k] = bool(fn(*a))
        except Exception:
            res[k] = False
    jobs = [("yt", http_ok, SITES["yt"]), ("ig", http_ok, SITES["ig"]), ("tg", tg_ok)]
    ths = [threading.Thread(target=one, args=j, daemon=True) for j in jobs]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout * 4 + 8)
    return {k: bool(res.get(k)) for k in ("yt", "ig", "tg")}


def live(c, xray, rounds, timeout, speed=False, secs=3.0, sites=False):
    port, tmp = free_port(), tempfile.mkdtemp(prefix="cfgscan_")
    env = dict(os.environ) if ANDROID else {k: v for k, v in os.environ.items()
           if k.upper() in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "COMSPEC", "USERPROFILE", "HOME")}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if c["proto"] in SB_PROTOS:  # sing-box فقط فایل می‌خونه؛ فایل چند ثانیه بعد از بالا اومدن حذف می‌شه
        path = os.path.join(tmp, "c.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(build_singbox(c, [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": port}]), f)
        p = subprocess.Popen([SINGBOX, "run", "-c", path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, cwd=tmp, env=env, creationflags=flags)
    else:  # کانفیگ xray (با اطلاعات محرمانه‌ی سرور) از stdin می‌ره و روی دیسک نوشته نمی‌شه
        p = subprocess.Popen([xray, "run", "-c", "stdin:"], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, cwd=tmp, env=env, creationflags=flags)
        try:
            p.stdin.write(json.dumps(build_xray(c, port)).encode("utf-8"))
            p.stdin.close()
        except OSError:
            pass
    lat, ok = [], 0
    try:
        t_end = time.time() + (9 if c["proto"] in SB_PROTOS else 6)
        while time.time() < t_end and p.poll() is None:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.2)
        for _ in range(rounds):
            try:
                st, _, ms = fetch(port, LAT_URL, timeout)
                if st == 204:
                    ok += 1
                    lat.append(ms)
            except ssl.SSLCertVerificationError:
                c["flags"].add("tls_verify_fail")
                break
            except Exception:
                pass
            time.sleep(0.4)
        if ok:
            try:
                _, body, _ = fetch(port, IP_URL, timeout)
                ip = body.decode("ascii", "ignore").strip()
                ipaddress.ip_address(ip)
                c["exit_ip"] = ip
            except Exception:
                pass
            try:
                st2, body, _ = fetch(port, PLAIN_URL, timeout)
                if st2 == 200:  # خطا/ریدایرکت/بلاک پورت 80 نتیجه‌ی نامعلومه، نه دستکاری
                    c["plain_hash"] = hashlib.sha256(body).hexdigest()[:16]
                    if b"Example Domain" not in body or b"<script" in body.lower() or len(body) > 5000:
                        c["flags"].add("tamper")
            except Exception:
                pass
            if sites:  # آیا یوتیوب و اینستاگرام و تلگرام واقعاً باز می‌شن؟
                c["sites"] = site_check(port, min(timeout, 5))
            if speed:  # سرعت واقعی دانلود از داخل تونل (فقط روی نامزدهای نهایی)
                k = measure_kbps(port, secs, 2, timeout)
                if k:
                    c["kbps"] = k
    finally:
        p.terminate()
        try:
            p.wait(3)
        except subprocess.TimeoutExpired:
            p.kill()
        shutil.rmtree(tmp, ignore_errors=True)
    c["rounds"], c["ok"] = rounds, ok
    c["success"] = round(ok / rounds, 2) if rounds else 0
    c["alive"] = ok > 0
    if lat:
        c["lat"] = int(statistics.mean(lat))
        c["jitter"] = int(statistics.pstdev(lat)) if len(lat) > 1 else 0
        if len(lat) > 2 and c["jitter"] > 0.5 * c["lat"] and c["jitter"] > 150:
            c["flags"].add("high_jitter")
    return c


# ---------------------------------------------------------------- history / scoring / classify








# ---------------------------------------------------------------- report




DEFAULT_SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub1.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub2.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub3.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub4.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub5.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub6.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub7.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Sub8.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vmess.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/trojan.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/ss.txt",
    "https://raw.githubusercontent.com/patterniha/Free-Configs/main/configs.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/high_volume_raw.txt",
    "https://raw.githubusercontent.com/kasesm/Free-Config/main/all_raw.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/secure/configs.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/all/configs.txt",
    "https://github.com/Epodonios/v2ray-configs/raw/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/morpheusadam/v2ray-config/main/subs/bundles/all.txt",
    "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/V2RAY_RAW.txt",
    "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
    "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/proxy_configs.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/main/mix/sub.html",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
]


RAW_RE = (r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(?:refs/heads/)?([^/]+)/(.+)$",
          r"^https://github\.com/([^/]+)/([^/]+)/raw/(?:refs/heads/)?([^/]+)/(.+)$")
JSD_HOSTS = ("cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net", "testingcf.jsdelivr.net")
GH_RAW_IPS = ("185.199.108.133", "185.199.109.133", "185.199.110.133", "185.199.111.133")
PIN_PORT = 443  # فقط برای تست عوض می‌شه
CA_FILE = ""  # مسیر بسته‌ی گواهی‌ها؛ cfgweb اگه فایل کنارش باشه مقدار می‌ده (روی اندروید مطمئن‌تر از گواهی‌های سیستم)


def _gh(u):
    for r in RAW_RE:
        m = re.match(r, u)
        if m:
            return m.groups()
    return None


def mirror_urls(u):
    """آدرس اصلی + آینه‌های CDN (وقتی raw.githubusercontent فیلتر باشه معمولاً اینا باز می‌مونن)."""
    out, m = [u], _gh(u)
    if m:
        user, repo, br, path = m
        out += [f"https://{h}/gh/{user}/{repo}@{br}/{path}" for h in JSD_HOSTS]
        out += [f"https://cdn.statically.io/gh/{user}/{repo}/{br}/{path}", f"https://raw.githack.com/{user}/{repo}/{br}/{path}"]
    return out


def _ssl_ctx():
    try:
        if CA_FILE and os.path.isfile(CA_FILE):
            return ssl.create_default_context(cafile=CA_FILE)
    except Exception:
        pass
    return ssl.create_default_context()


def classify(e):
    """علت شکست دانلود به یک برچسب کوتاه."""
    if isinstance(e, urllib.error.HTTPError):
        return f"http{e.code}"
    r = getattr(e, "reason", e)
    if isinstance(r, ssl.SSLError) or isinstance(e, ssl.SSLError):
        return "ssl"
    if isinstance(r, socket.gaierror):
        return "dns"
    if isinstance(r, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(r, ConnectionRefusedError):
        return "refused"
    if isinstance(r, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    return "other"


FAIL_WHY = {"dns": "DNS خراب یا مسدود", "timeout": "کند یا بسته (timeout)", "ssl": "خطای گواهی TLS",
            "reset": "قطع اتصال از طرف شبکه", "refused": "اتصال رد شد", "other": "خطای شبکه"}


def why_text(stats):
    """مهم‌ترین علت شکست بین همه‌ی منبع‌ها، به فارسی."""
    cnt = {}
    for v in stats.values():
        for k, n in (v.get("errs") or {}).items():
            cnt[k] = cnt.get(k, 0) + n
    if not cnt:
        return "علت نامشخص"
    k = max(cnt, key=cnt.get)
    return FAIL_WHY.get(k, f"پاسخ خطا از سرور ({k})")


class _Pinned(http.client.HTTPSConnection):
    """اتصال مستقیم به IP مشخص با SNI و بررسی گواهی برای نام اصلی (وقتی DNS خراب یا آلوده‌ست)."""

    def __init__(self, host, ip, port, ctx, timeout):
        super().__init__(host, timeout=timeout, context=ctx)
        self._ip, self._port = ip, port

    def connect(self):
        sock = socket.create_connection((self._ip, self._port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def get_pinned(host, ip, path, ctx, timeout, port=443):
    conn = _Pinned(host, ip, port, ctx, timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity"})
        r = conn.getresponse()
        if r.status != 200:
            raise urllib.error.HTTPError(path, r.status, "", None, None)
        return r.read(MAX_SUB_BYTES)
    finally:
        conn.close()


def attempts(u, via=False):
    """ترتیب تلاش‌ها: مستقیم، از طریق پروکسی محلی (اگه وصله)، آینه‌ها، و در آخر اتصال با IP ثابت GitHub."""
    if not (public_url(u) or is_channel_url(u)):
        return []  # دفاع دوم: برای آدرس داخلی هیچ تلاشی (مستقیم، via، آینه) برنامه‌ریزی نمی‌شه
    if is_channel_url(u):
        return [("chan", "direct")] + ([("chan", "via")] if via else [])
    ms = mirror_urls(u)
    plan = [("direct", ms[0])] + ([("via", u)] if via else []) + [("direct", m) for m in ms[1:]]
    g = _gh(u)
    if g:
        k = sum(map(ord, u)) % len(GH_RAW_IPS)
        for ip in (GH_RAW_IPS[k], GH_RAW_IPS[(k + 1) % len(GH_RAW_IPS)]):
            plan.append(("pin", ("raw.githubusercontent.com", ip, f"/{g[0]}/{g[1]}/{g[2]}/{g[3]}", PIN_PORT)))
    return plan


def _private_ip(ip):
    ip = getattr(ip, "ipv4_mapped", None) or ip  # ::ffff:127.0.0.1 باید با بخش IPv4 خودش قضاوت بشه
    return non_public(ip)  # خصوصی، loopback، link-local، CGNAT، رزرو و multicast


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """ریدایرکت فقط به https و آدرس عمومی. قبلاً یک منبع (یا کانال) می‌تونست با 302 ما رو به http://127.0.0.1 ،
    شبکه‌ی داخلی یا ftp:// بفرسته."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        nu = urllib.parse.urljoin(req.full_url, newurl)
        if not nu.lower().startswith("https://") or not public_url(nu):
            raise urllib.error.HTTPError(req.full_url, code, "unsafe redirect", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, nu)  # آدرس مطلق‌شده


class _GuardConn(http.client.HTTPSConnection):
    """قبل از اتصال، همه‌ی IPهای نام رو می‌گیره و اگه داخلی بودن رد می‌کنه؛ به همون IP بررسی‌شده وصل می‌شه (DNS rebinding).
    فقط برای اتصال مستقیم؛ مسیر پروکسی محلی از این رد نمی‌شه."""

    def connect(self):
        last = OSError("no address")
        for fam, typ, proto, _, sa in socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM):
            if _private_ip(ipaddress.ip_address(sa[0].split("%")[0])):
                last = socket.gaierror("private address blocked")  # DNS آلوده‌ی بعضی شبکه‌ها؛ علتش «DNS خراب» حساب بشه
                continue
            s = socket.socket(fam, typ, proto)
            try:
                if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    s.settimeout(self.timeout)
                s.connect(sa)
            except OSError as e:
                s.close()
                last = e
                continue
            self.sock = self._context.wrap_socket(s, server_hostname=self.host)
            return
        raise last


class _GuardHTTPConn(http.client.HTTPConnection):
    """همان نگهبان برای http:// ساده (قبلاً فقط https بررسی می‌شد و http://127.0.0.1 خوانده می‌شد)."""

    def connect(self):
        last = OSError("no address")
        for fam, typ, proto, _, sa in socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM):
            if _private_ip(ipaddress.ip_address(sa[0].split("%")[0])):
                last = socket.gaierror("private address blocked")
                continue
            s = socket.socket(fam, typ, proto)
            try:
                if self.timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                    s.settimeout(self.timeout)
                s.connect(sa)
            except OSError as e:
                s.close()
                last = e
                continue
            self.sock = s
            return
        raise last


class _GuardHTTP(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_GuardHTTPConn, req)


class _GuardHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_GuardConn, req, context=self._context)


def safe_opener(ctx=None):
    """اتصال مستقیم امن برای دریافت منبع‌ها: بدون پروکسی سیستم، IP داخلی رد، ریدایرکت فقط https عمومی."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _GuardHTTP(),
                                       _GuardHTTPS(context=ctx or ssl.create_default_context()), _SafeRedirect())


def _openers(ctx, proxy_port=None):
    """(مستقیم، از طریق پروکسی محلی یا None)؛ هر دو با ریدایرکت امن. مستقیم: بدون پروکسی سیستم و با نگهبان DNS."""
    hs, sr = urllib.request.HTTPSHandler(context=ctx), _SafeRedirect()
    direct = safe_opener(ctx)
    via = (urllib.request.build_opener(urllib.request.ProxyHandler(
        {"https": f"http://127.0.0.1:{proxy_port}", "http": f"http://127.0.0.1:{proxy_port}"}), hs, sr) if proxy_port else None)
    return direct, via


GH_API = "https://api.github.com"
DISC_QUERIES = ("v2ray free config", "vless vmess trojan subscription", "xray free servers list")
_DISC_NAME = re.compile(r"(?i)(v2ray|vless|vmess|trojan|hysteria|hy2|tuic|shadowsocks|sub|config|mix|proxy|server|free|all|normal)")


def _int(x, hi=10 ** 9):
    try:
        return max(0, min(int(x), hi))
    except (TypeError, ValueError, OverflowError):
        return 0


def _safe_branch(b):
    return bool(re.fullmatch(r"[\w.-]{1,100}(?:/[\w.-]{1,100}){0,3}", b)) and ".." not in b.split("/")


def _safe_path(p):
    """مسیر فایل توی ریپو: بدون . و .. و بک‌اسلش و کاراکتر کنترلی (وگرنه URL به جای دیگه‌ای می‌ره)."""
    return (not re.search(r"[\x00-\x1f\x7f\\]", p) and not p.startswith("/")
            and all(s not in ("", ".", "..") for s in p.split("/")))


def discover_github(opener, log=lambda m: None, stop=None, max_repos=10, per_repo=5):
    """ریپوهای تازه‌ی گیت‌هاب که فایل لیست کانفیگ دارن رو پیدا می‌کنه. (آدرس‌های raw، اطلاعات)
    فقط پیشنهاده؛ هر آدرس قبل از اضافه شدن جداگانه دانلود و شمرده می‌شه. محدودیت نرخ API رو تشخیص می‌ده و متوقف می‌شه."""
    stop = stop or (lambda: False)
    info = {"rate": False, "err": "", "repos": 0}

    def api(path):
        rq = urllib.request.Request(GH_API + path, headers={"User-Agent": "ConfigTool", "Accept": "application/vnd.github+json"})
        with opener.open(rq, timeout=15) as r:
            return json.loads(r.read(2_000_000).decode("utf-8", "replace"))
    since = time.strftime("%Y-%m-%d", time.gmtime(time.time() - 10 * 86400))
    repos, seen = [], set()
    for q in DISC_QUERIES:
        if stop() or info["rate"]:
            break
        try:
            d = api("/search/repositories?q=" + urllib.parse.quote(f"{q} pushed:>{since}") + "&sort=updated&order=desc&per_page=12")
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                info["rate"] = True
            else:
                info["err"] = f"http {e.code}"
            continue
        except Exception as e:
            info["err"] = classify(e)
            continue
        items = d.get("items") if isinstance(d, dict) else None
        for it in (items if isinstance(items, list) else []):
            if not isinstance(it, dict):  # پاسخ خراب یا غیرمنتظره نباید کل جستجو رو بندازه
                continue
            fn = str(it.get("full_name") or "")
            br = str(it.get("default_branch") or "main")
            if (not re.fullmatch(r"[\w.-]{1,60}/[\w.-]{1,100}", fn) or fn in seen or it.get("fork") or it.get("archived")
                    or it.get("private") or not it.get("size") or not _safe_branch(br)):
                continue
            seen.add(fn)
            repos.append((fn, br, _int(it.get("stargazers_count"))))
    repos = sorted(repos, key=lambda r: -r[2])[:max_repos]
    urls = []
    for fn, br, _ in repos:
        if stop() or info["rate"]:
            break
        try:
            t = api(f"/repos/{fn}/git/trees/{urllib.parse.quote(br)}?recursive=1")
        except urllib.error.HTTPError as e:
            info["rate"] = info["rate"] or e.code in (403, 429)
            continue
        except Exception as e:
            info["err"] = classify(e)
            continue
        picked = []
        tree = t.get("tree") if isinstance(t, dict) else None
        for e in (tree if isinstance(tree, list) else []):
            if not isinstance(e, dict):
                continue
            path, size = str(e.get("path") or ""), _int(e.get("size"))
            low = path.lower()
            if (e.get("type") != "blob" or not low.endswith(".txt") or not 2000 <= size <= 3_000_000 or low.count("/") > 3
                    or len(path) > 300 or not _safe_path(path) or not _DISC_NAME.search(low.rsplit("/", 1)[-1])):
                continue
            picked.append((size, path))
        for size, path in sorted(picked, reverse=True)[:per_repo]:
            u = f"https://raw.githubusercontent.com/{fn}/{br}/" + "/".join(urllib.parse.quote(x) for x in path.split("/"))
            if public_url(u):
                urls.append(u)
        info["repos"] += 1
    return urls, info


def fetch_sources(urls, per_source=400, log=print, origin=None, stop=None, proxy_port=None, deadline=60):
    """از چند منبع هم‌زمان می‌گیره. هر منبع چند راه داره و اولین موفق برنده‌ست. (links, آمار)"""
    import random
    import threading
    from concurrent.futures import wait
    stop = stop or (lambda: False)
    ctx = _ssl_ctx()
    direct, via = _openers(ctx, proxy_port)
    urls = [u for u in urls if re.match(r"^https://", u, re.I) and (public_url(u) or is_channel_url(u))]  # تنها دروازه: آدرس داخلی هرگز به برنامه‌ی دریافت (مستقیم یا via) نمی‌رسه
    done = {u: threading.Event() for u in urls}
    got, errs = {}, {u: {} for u in urls}

    def attempt(u, kind, a):
        if done[u].is_set() or stop():
            return
        try:
            if kind == "chan":
                op = via if a == "via" else direct

                def get(p, op=op):
                    rq = urllib.request.Request(p, headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "en"})
                    with op.open(rq, timeout=9) as r:
                        return r.read(MAX_SUB_BYTES).decode("utf-8", "replace")
                ls, subs = channel_links(u, get)
                for sb in subs:
                    try:
                        ls += extract_links(get(sb))
                    except Exception:
                        pass
                ls = list(dict.fromkeys(ls))
                if ls and not done[u].is_set():
                    got[u] = ls
                    done[u].set()
                return
            if kind == "pin":
                raw = get_pinned(a[0], a[1], a[2], ctx, 8, a[3])
            else:
                req = urllib.request.Request(a, headers={"User-Agent": "Mozilla/5.0"})
                with (via if kind == "via" else direct).open(req, timeout=8) as r:
                    raw = r.read(MAX_SUB_BYTES)
            ls = list(dict.fromkeys(extract_links(raw.decode("utf-8", "replace"))))
            if ls and not done[u].is_set():
                got[u] = ls
                done[u].set()
        except Exception as e:
            k = classify(e)
            errs[u][k] = errs[u].get(k, 0) + 1

    plans = {u: attempts(u, bool(via)) for u in urls}
    ex = ThreadPoolExecutor(max_workers=24)
    futs = []
    for i in range(max((len(p) for p in plans.values()), default=0)):
        for u in urls:  # دور به دور بین منبع‌ها، تا همه اول راه‌های سریع رو امتحان کنن
            if i < len(plans[u]):
                futs.append(ex.submit(attempt, u, *plans[u][i]))
    try:
        wait(futs, timeout=deadline)
    except Exception:
        pass
    ex.shutdown(wait=False, cancel_futures=True)
    stats, seen, out = {}, set(), []
    for u in urls:
        ls = got.get(u, [])
        random.shuffle(ls)
        ls = ls[:per_source]
        top = max(errs[u], key=errs[u].get) if errs[u] and not ls else ""
        stats[u] = {"got": len(ls), "err": top, "errs": dict(errs[u]) if not ls else {}}
        for l in ls:
            if l not in seen:
                seen.add(l)
                out.append(l)
                if origin is not None:
                    origin[l] = u
    log(f"{len(out)} لینک یکتا از {sum(1 for v in stats.values() if v['got'])} منبع")
    return out, stats










