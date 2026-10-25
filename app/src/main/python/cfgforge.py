"""cfgforge - ساخت کانفیگ کامل کلاینت xray (تک‌سرور یا چندسرور با balancer)، مسدودسازی تبلیغ،
مسیر مستقیم سایت‌های داخلی و ترفندهای کمکی (fragment/mux)."""
from cfgscan import build_xray, LAT_URL, android_dns

PROFILES = {
    "balanced": dict(fragment=True, mux=True, strategy="leastPing", only_encrypted=False, desc="متعادل"),
    "speed": dict(fragment=True, mux=False, strategy="leastPing", only_encrypted=False, desc="سرعت"),
    "stable": dict(fragment=True, mux=False, strategy="leastPing", only_encrypted=False, desc="پایداری"),
    "secure": dict(fragment=True, mux=False, strategy="leastPing", only_encrypted=True, desc="امنیت بیشتر"),
    "upload": dict(fragment=False, mux=False, strategy="leastPing", only_encrypted=False, desc="بیشترین آپلود"),  # بدون mux (سرعتِ آپلودِ یک جریانِ بزرگ رو می‌خوابونه) و بدون خرد کردن بسته‌ها
}
CALL = [False]  # حالت تماس: فقط یک خروجی ثابت (بدون balancer)، بدون mux و sniffing، با مهلت بی‌کاری بلندتر
COUNTRY_DIRECT = {"ir": ["domain:ir", "geosite:category-ir"], "az": ["domain:az"], "tr": ["domain:tr"],
                  "ru": ["domain:ru"], "cn": ["geosite:geolocation-cn"]}




def ob_of(c, tag):
    ob = build_xray(c, 0)["outbounds"][0]
    ob["tag"] = tag
    return ob


def set_dialer(ob, tag):
    ob.setdefault("streamSettings", {}).setdefault("sockopt", {})["dialerProxy"] = tag


def make_client(cfgs, prof, chain, direct, sport, hport, probe_interval="30s", strategy=None, plain=False, block_ads=False,
                direct_country=""):
    P = PROFILES[prof]
    call = CALL[0]
    if chain or call:
        cfgs = cfgs[:1]  # زنجیره فقط یک هاپ اول می‌گیره؛ در حالت تماس هم balancer (leastPing) وسط تماس خروجی رو عوض می‌کرد و تماس می‌پرید
    obs, use_frag = [], False
    for i, c in enumerate(cfgs, 1):
        ob = ob_of(c, f"proxy-{i}")
        if (P["fragment"] and not plain and c["security"] == "tls") or c.get("frag"):
            set_dialer(ob, "fragment")
            use_frag = True
        if P["mux"] and not call and not plain and c["network"] == "ws" and c["proto"] != "ss" and not c["flow"]:
            ob["mux"] = {"enabled": True, "concurrency": 8}
        obs.append(ob)
    if chain:
        own = ob_of(chain, "own")
        set_dialer(own, "proxy-1")
        obs.insert(0, own)
    obs += [{"tag": "direct", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]
    if use_frag:
        obs.append({"tag": "fragment", "protocol": "freedom",
                    "settings": {"fragment": {"packets": "tlshello", "length": "100-200", "interval": "10-20"}}})

    sniff = {"enabled": not call, "destOverride": ["http", "tls", "quic"], "routeOnly": True}
    rules = [{"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"},
             {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}]
    if direct:
        rules.append({"type": "field", "domain": direct, "outboundTag": "direct"})
    if block_ads:  # تبلیغ و ردیاب‌ها: هم امن‌تر هم سبک‌تر
        rules.insert(1, {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"})
    cc = (direct_country or "").lower()
    if cc in COUNTRY_DIRECT:  # سایت‌های داخلی مستقیم؛ سریع‌تر و بدون ترافیک غیرعادی از پروکسی
        rules.append({"type": "field", "domain": COUNTRY_DIRECT[cc], "outboundTag": "direct"})
        rules.append({"type": "field", "ip": [f"geoip:{cc}"], "outboundTag": "direct"})
    final = {"type": "field", "network": "tcp,udp"}
    multi = len(cfgs) > 1 and not chain
    if multi:
        final["balancerTag"] = "bal"
    else:
        final["outboundTag"] = "own" if chain else "proxy-1"
    rules.append(final)

    cfg = {"log": {"loglevel": "warning"},
           "inbounds": [
               {"tag": "socks-in", "listen": "127.0.0.1", "port": sport, "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True}, "sniffing": sniff},
               {"tag": "http-in", "listen": "127.0.0.1", "port": hport, "protocol": "http", "sniffing": sniff}],
           "outbounds": obs,
           "routing": {"domainStrategy": "AsIs", "rules": rules}}
    if call:  # سشن‌های UDP بی‌صدا (قطع میکروفون/hold) نباید زود بسته بشن
        cfg["policy"] = {"levels": {"0": {"connIdle": 600, "handshake": 8}}}
    if multi:
        cfg["routing"]["balancers"] = [{"tag": "bal", "selector": ["proxy-"], "strategy": {"type": strategy or P["strategy"]}}]
        cfg["observatory"] = {"subjectSelector": ["proxy-"], "probeUrl": LAT_URL, "probeInterval": probe_interval, "enableConcurrency": True}
    return android_dns(cfg), cfgs
















