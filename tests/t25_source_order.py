import sys, os, random, tempfile
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W
W.learn_reset(); W.NETID[0] = "a:TESTNET000"
G = dict(yt=1, ig=1, tg=1)
def mk(src, i):
    return {"proto": "vless", "network": "ws", "security": "tls", "port": 443, "srcurl": src, "raw": f"vless://{src}{i}", "host": "h", "alive": True, "sites": {}}
BIG, GOOD, BAD = "https://big.example/all.txt", "https://good.example/small.txt", "https://bad.example/junk.txt"
# تجربه: GOOD اغلب سالمه، BAD هیچ‌وقت
for _ in range(60):
    g = mk(GOOD, 0); W.learn_record(g, "live"); W.learn_record(dict(g, sites=G), "site")
    b = mk(BAD, 0); b["alive"] = False; W.learn_record(b, "live")
assert W.src_score(GOOD) > 3 * W.src_score(BAD); print("scores good %.2f unknown %.2f bad %.2f" % (W.src_score(GOOD), W.src_score(BIG), W.src_score(BAD)))
items = [mk(BIG, i) for i in range(2500)] + [mk(BAD, i) for i in range(800)] + [mk(GOOD, i) for i in range(40)]
random.shuffle(items)
items.sort(key=lambda c: (c["srcurl"], c["raw"]))   # بدترین حالت: منبع غول‌پیکر اول
out = W.src_interleave(items)
assert len(out) == len(items) and len({c["raw"] for c in out}) == len(items)   # هیچ‌چیز گم یا تکراری نمی‌شه
pos = [i for i, c in enumerate(out) if c["srcurl"] == GOOD]
print("good source (40 items) finishes by position", pos[-1], "of", len(out), "| plain order would be", len(items) - 1)
assert pos[-1] < 400, "good source still buried"
first = out[:200]
cnt = lambda u: sum(1 for c in first if c["srcurl"] == u)
print("first 200 tests -> good %d | big %d | bad %d" % (cnt(GOOD), cnt(BIG), cnt(BAD)))
assert cnt(GOOD) > cnt(BAD) and cnt(BIG) > 0 and cnt(BAD) < 40   # منبع بد کم، ولی هیچ منبعی صفر نیست (کاوش)
# ترتیب داخل هر منبع حفظ می‌شه
sub = [c["raw"] for c in out if c["srcurl"] == BIG]; assert sub == sorted(sub)
# یک منبع: همون لیست
one = [mk(BIG, i) for i in range(5)]; assert W.src_interleave(one) == one
print("ALL OK")
