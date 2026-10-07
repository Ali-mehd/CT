"""cfgscan - تجزیه‌ی لینک کانفیگ‌ها (vmess/vless/trojan/ss/hysteria2/tuic/anytls)، تست واقعی از شبکه‌ی خود کاربر،
فهرست سیاه IP و دریافت منابع. فقط کتابخانه‌ی استاندارد پایتون؛ برای تست زنده به xray و sing-box نیاز داره."""
import base64, hashlib, html as _html, ipaddress, json, os, re, shutil, socket, ssl
import statistics, struct, subprocess, tempfile, time, urllib.parse, urllib.request
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
             mode="", extra="", frag=False, obfs="", obfspw="", cc="", urm="")
    d.update(kw)
    return d


def p_vmess(link):
    j = json.loads(b64d(link[8:]))
    return mk(proto="vmess", host=clean(j.get("add")), port=int(j.get("port")),
              id=clean(j.get("id")), aid=int(j.get("aid") or 0), scy=clean(j.get("scy") or "auto", 20),
              network=clean(j.get("net") or "tcp", 20).lower(),
              security="tls" if j.get("tls") == "tls" else "none",
              sni=clean(j.get("sni")), hosthdr=clean(j.get("host")), path=clean(j.get("path"), 512),
              svc=clean(j.get("path"), 128), fp=clean(j.get("fp"), 30), alpn=clean(j.get("alpn"), 60),
              insecure=str(j.get("allowInsecure", "")).lower() in ("1", "true"), name=clean(j.get("ps"), 80))


def p_url(link, sch):
    u = urllib.parse.urlsplit(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    ident = urllib.parse.unquote(u.username or "")
    sec = (q.get("security") or ("tls" if sch == "trojan" else "none")).lower()
    return mk(proto=sch, host=clean(u.hostname), port=u.port or 0,
              id=clean(ident) if sch == "vless" else "", pw=clean(ident) if sch == "trojan" else "",
              network=clean(q.get("type") or "tcp", 20).lower(), security=sec,
              sni=clean(q.get("sni") or q.get("peer")), hosthdr=clean(q.get("host")),
              path=clean(urllib.parse.unquote(q.get("path", "")), 512), svc=clean(q.get("serviceName"), 128),
              flow=clean(q.get("flow"), 40), mode=clean(q.get("mode"), 20), extra=clean(q.get("extra"), 2000), pbk=clean(q.get("pbk"), 100), sid=clean(q.get("sid"), 40),
              fp=clean(q.get("fp"), 30), alpn=clean(q.get("alpn"), 60),
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


def p_hy2(link):
    u, q = _q(link)
    pw = urllib.parse.unquote(u.username or "") + (":" + urllib.parse.unquote(u.password) if u.password else "")
    return mk(proto="hysteria2", host=clean(u.hostname), port=u.port or 443, pw=clean(pw), security="tls",
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


def extract_links(text):
    if "://" not in text[:200]:
        try:
            text = b64d(text)
        except Exception:
            pass
    text = _html.unescape(text)  # برای صفحه‌هایی مثل t.me/s/کانال
    return re.findall(r"(?:vmess|vless|trojan|ss|hysteria2|hy2|tuic|anytls)://[^\s\"'<>]+", text)




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
    elif c["network"] not in NETS or c["security"] not in ("none", "tls", "reality") or c["plugin"]:
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
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
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
    for i in infos:
        ip = ipaddress.ip_address(i[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            c["flags"].add("private_addr")
            return c
        if BLOCK.contains(ip):  # قبل از هر اتصالی؛ آنتی‌ویروس هم همین آدرس‌ها رو می‌بنده
            c["flags"].add("blocklisted")
            return c
    c["ip"] = infos[0][4][0].split("%")[0]  # همین آی‌پیِ بررسی‌شده توی کانفیگ می‌ره (جلوگیری از DNS rebinding)
    if c["proto"] in ("hysteria2", "tuic"):  # UDP: با TCP نمی‌شه سنجید؛ تست واقعی خودش تصمیم می‌گیره
        c["reachable"], c["tcp_ms"] = True, None
        return c
    t0 = time.time()
    try:
        socket.create_connection((c["host"], c["port"]), timeout=timeout).close()
        c["reachable"], c["tcp_ms"] = True, int((time.time() - t0) * 1000)
    except OSError:
        pass
    return c


# ---------------------------------------------------------------- live test via xray
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
    return int(head.split(b" ", 2)[1]), body, int((time.time() - t0) * 1000)


def live(c, xray, rounds, timeout, speed=False):
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
            if speed:  # سرعت واقعی دانلود از داخل تونل (فقط در حالت «سرعت» و روی نامزدهای نهایی)
                for su in SPEED_URLS:
                    try:
                        t1 = time.time()
                        st3, body, _ = fetch(port, su, timeout + 5, limit=600_000)
                        dt = max(time.time() - t1, 0.05)
                        if st3 == 200 and len(body) > 50_000:
                            c["kbps"] = int(len(body) * 8 / 1000 / dt)
                            break
                    except Exception:
                        pass
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


def mirror_urls(u):
    """آدرس اصلی + آینه‌های jsDelivr (وقتی raw.githubusercontent فیلتر باشه معمولاً اینا باز می‌مونن)."""
    m = (re.match(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/(?:refs/heads/)?([^/]+)/(.+)$", u)
         or re.match(r"^https://github\.com/([^/]+)/([^/]+)/raw/(?:refs/heads/)?([^/]+)/(.+)$", u))
    out = [u]
    if m:
        user, repo, br, path = m.groups()
        out += [f"https://{h}/gh/{user}/{repo}@{br}/{path}"
                for h in ("cdn.jsdelivr.net", "fastly.jsdelivr.net", "gcore.jsdelivr.net")]
    return out


def fetch_sources(urls, per_source=400, log=print, origin=None, stop=None, proxy_port=None, deadline=60):
    """از چند منبع هم‌زمان می‌گیره (با آینه و در صورت وجود از طریق پروکسی محلی). (links, آمار)"""
    import random
    from concurrent.futures import as_completed
    stop = stop or (lambda: False)
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    via = (urllib.request.build_opener(urllib.request.ProxyHandler(
        {"https": f"http://127.0.0.1:{proxy_port}", "http": f"http://127.0.0.1:{proxy_port}"})) if proxy_port else None)

    def get(op, u):
        req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0"})
        with op.open(req, timeout=10) as r:
            return list(dict.fromkeys(extract_links(r.read(MAX_SUB_BYTES).decode("utf-8", "replace"))))

    def one(u):
        err = ""
        if not re.match(r"^https://", u, re.I):
            return u, [], "only https"
        tries = [(direct, m) for m in mirror_urls(u)] + ([(via, u)] if via else [])
        for op, m in tries:
            if stop():
                break
            try:
                ls = get(op, m)
                if ls:
                    random.shuffle(ls)
                    return u, ls[:per_source], ""
            except Exception as e:
                err = str(e)[:60]
        return u, [], err

    ex = ThreadPoolExecutor(max_workers=8)
    futs = [ex.submit(one, u) for u in urls]
    res = []
    try:
        for f in as_completed(futs, timeout=deadline):
            res.append(f.result())
            if stop():
                break
    except Exception:
        pass
    ex.shutdown(wait=False, cancel_futures=True)
    stats, seen, out = {}, set(), []
    for u, ls, err in res:
        stats[u] = {"got": len(ls), "err": err}
        for l in ls:
            if l not in seen:
                seen.add(l)
                out.append(l)
                if origin is not None:
                    origin[l] = u
    log(f"{len(out)} لینک یکتا از {sum(1 for v in stats.values() if v['got'])} منبع")
    return out, stats










