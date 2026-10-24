import sys, os, random, tempfile, time
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W, netprobe
W.learn_reset()
def mk(proto, net, sec, port, alive=True):
    return {"proto": proto, "network": net, "security": sec, "port": port, "srcurl": "", "raw": f"{proto}://H{random.random()}", "host": "H", "alive": alive, "sites": {}}
G = dict(yt=1, ig=1, tg=1)
# 1) نوع اتصال: همیشه رشته است و کرش نمی‌کنه
k = netprobe.net_kind(); assert isinstance(k, str); print("net_kind ->", repr(k))
# 2) نت همراه: vless خوب، vmess بد. شبکه‌ی خونه: برعکس
W.NETID[0] = "a:MOBILE0000"
for _ in range(80):
    g = mk("vless", "ws", "tls", 443); W.learn_record(g, "live"); W.learn_record(dict(g, sites=G), "site")
    b = mk("vmess", "tcp", "none", 80, alive=False); W.learn_record(b, "live")
m_good, m_bad = W.learn_score(mk("vless", "ws", "tls", 443)), W.learn_score(mk("vmess", "tcp", "none", 80))
assert m_good > 3 * m_bad; print("mobile learned: good %.2f bad %.2f" % (m_good, m_bad))
# 3) شبکه‌ی تازه (مودم): نباید به اندازه‌ی نت همراه تحت‌تأثیر باشه
W.NETID[0] = "a:HOMEMODEM0"
h_good, h_bad = W.learn_score(mk("vless", "ws", "tls", 443)), W.learn_score(mk("vmess", "tcp", "none", 80))
print("new network: good %.2f bad %.2f" % (h_good, h_bad))
assert (h_good - h_bad) < 0.5 * (m_good - m_bad), "mobile lessons leaked into the new network"
# 4) مودم خودش یاد می‌گیره و برعکسِ نت همراه می‌شه
for _ in range(80):
    g = mk("vmess", "tcp", "none", 80); W.learn_record(g, "live"); W.learn_record(dict(g, sites=G), "site")
    b = mk("vless", "ws", "tls", 443, alive=False); W.learn_record(b, "live")
assert W.learn_score(mk("vmess", "tcp", "none", 80)) > W.learn_score(mk("vless", "ws", "tls", 443))
W.NETID[0] = "a:MOBILE0000"
assert W.learn_score(mk("vless", "ws", "tls", 443)) > W.learn_score(mk("vmess", "tcp", "none", 80))
print("each network keeps its own lessons: OK")
# 5) لیست آماده‌ها: تب و جابه‌جایی یکی می‌بینن
a, b, c = [{"host": h, "port": 1, "raw": h, "strikes": s} for h, s in (("a", 0), ("b", 2), ("c", 0))]
W.POOL.update(standby=[a, b, c], bad={("c", 1): time.time() + 500})
assert [x["host"] for x in W.standby_ok()] == ["a"]
print("standby list consistent: OK")
print("ALL OK")
