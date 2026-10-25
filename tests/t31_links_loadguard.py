import sys, os, random, tempfile
os.environ["CFG_DATA"] = tempfile.mkdtemp()
os.environ["CFG_LOADGUARD"] = "0"   # توی تست نخ اندازه‌گیری راه نیفته
sys.path.insert(0, '.')
import cfgweb as W
random.seed(3)
W.learn_reset(); W.NETID[0] = "a:TESTNET000"
G = dict(yt=1, ig=1, tg=1)

# ---------- balance_links
def mk(src, i):
    return {"proto": "vless", "network": "ws", "security": "tls", "port": 443, "srcurl": src, "raw": "x", "host": "h", "alive": True, "sites": {}}
GOOD, BAD, BIG = "https://good.example/g.txt", "https://bad.example/b.txt", "https://big.example/all.txt"
for _ in range(60):
    g = mk(GOOD, 0); W.learn_record(g, "live"); W.learn_record(dict(g, sites=G), "site")
    b = mk(BAD, 0); b["alive"] = False; W.learn_record(b, "live")
org, links = {}, []
for u, n in ((BIG, 30000), (BAD, 4000), (GOOD, 300)) :
    for i in range(n):
        l = f"vless://{u}#{i}"; org[l] = u; links.append(l)
random.shuffle(links)
cap = 9000
out = W.balance_links(links, org, cap)
cnt = lambda u: sum(1 for l in out if org[l] == u)
print("cap %d -> out %d | good %d/300 | bad %d/4000 | big %d/30000" % (cap, len(out), cnt(GOOD), cnt(BAD), cnt(BIG)))
assert len(out) == cap and len(set(out)) == cap and set(out) <= set(links)
assert cnt(GOOD) == 300, "small good source must stay whole (plain shuffle+cut would keep only ~%d)" % (300 * cap // len(links))
assert cnt(BAD) < 0.5 * 4000 and cnt(BAD) >= cap // 12, "known-bad source keeps only a floor + small share (but is not erased)"
assert cnt(BIG) > 0
# زیر سقف: همه می‌مونن
small = links[:500]; o2 = W.balance_links(small, org, cap); assert sorted(o2) == sorted(small)
# منبع‌های خیلی زیاد (کف صفر می‌شه) هم دقیقاً سقف رو پر می‌کنه
org3, l3 = {}, []
for s in range(200):
    for i in range(100):
        l = f"vless://s{s}#{i}"; org3[l] = f"https://s{s}.example/x"; l3.append(l)
o3 = W.balance_links(l3, org3, 1000); assert len(o3) == 1000 and len(set(o3)) == 1000
per = {}
for l in o3: per[org3[l]] = per.get(org3[l], 0) + 1
assert len(per) >= 100, "every source should get a chance when there are many"
# لینک بدون منبع (origin خالی) هم گم نمی‌شه
o4 = W.balance_links(["a", "b", "c"], {}, 2); assert len(o4) == 2
print("balance_links: OK")

# ---------- LoadGuard (AIMD)
L = W.LoadGuard()
assert L.apply({"live": 12, "rate": 60, "workers": 64}, "turbo") == {"live": 12, "rate": 60, "workers": 64}   # بدون فشار: دست نمی‌خوره
for _ in range(6): L.update(0.6, 0.2, 0.45)           # پردازه خفه شده (دیرکرد بالا)
assert L.f == L.MIN, L.f
p = L.apply({"live": 12, "rate": 60, "workers": 64}, "turbo")
assert p["live"] == 4 and p["rate"] == 60 * L.MIN and p["workers"] == 64, p
for _ in range(40): L.update(0.02, 0.2, 0.45)         # فشار رفت: آروم برمی‌گرده
assert L.f == 1.0, L.f
L2 = W.LoadGuard()
for _ in range(6): L2.update(0.02, 0.9, 0.25)         # CPU از سقف رد شده (دیرکرد کم ولی گرمازا)
assert L2.f < 0.5, L2.f
lo = W.LoadGuard(); lo.f = lo.MIN
assert lo.apply({"live": 2, "rate": 4, "workers": 8}, "gentle")["live"] >= 2 and lo.apply({"live": 2, "rate": 4, "workers": 8}, "gentle")["rate"] >= 3
sn = L2.snapshot(); assert sn["f"] < 0.5 and sn["min_f"] <= sn["f"] and sn["steps"] == 6 and sn["log"] and sn["avg_duty"] > 0.5
assert W.LOAD.snapshot()["on"] is False                # با CFG_LOADGUARD=0 هیچ نخی راه نمی‌افته
os.environ["CFG_ANDROID"] = "1"
p = W.speed_params(); assert p["live"] <= 12 and p["workers"] <= 64 and p["rate"] > 0, p
assert W.LOAD._th is None
del os.environ["CFG_ANDROID"]
if W.resource is not None:
    assert W.LoadGuard._cpu() >= 0
print("LoadGuard: OK")

# ---------- src_interleave با ضریب زنده: منبعی که همین الان سالم می‌ده جلو می‌افته، منبع بی‌نتیجه عقب (ولی حذف نمی‌شه)
A, B = "https://a.example/a.txt", "https://b.example/b.txt"
items = [mk(A, i) for i in range(200)] + [mk(B, i) for i in range(200)]
for i, c in enumerate(items): c["raw"] = f"r{i}"
base = W.src_interleave(items)
boost = W.src_interleave(items, lambda u: 6.0 if u == B else 0.1)
pos = lambda out, u: sum(i for i, c in enumerate(out) if c["srcurl"] == u) / 200
print("avg position of B: plain %.0f | boosted %.0f of 400" % (pos(base, B), pos(boost, B)))
assert pos(boost, B) < pos(base, B) - 40 and len(boost) == 400 and len({c["raw"] for c in boost}) == 400
print("live source adjustment: OK")

# ---------- گزارش: منبع ضعیف با برچسب و yield=۰
import evolve
m = evolve._metrics({"stats": {"tested": 10, "alive": 1, "reach": 5},
    "sources": [{"src": "a/b/c.txt", "on": True, "yield": 0.0}, {"src": "d/e/f.txt", "on": True, "yield": 0.2},
                {"src": "g/h/i.txt", "on": True, "yield": None}, {"src": "j/k/l.txt", "on": False, "yield": 0.0}]}) if hasattr(evolve, "_metrics") else None
if m is not None:
    assert m["sources_weak"] == ["a/b/c.txt"], m["sources_weak"]
    print("sources_weak: OK")
print("ALL OK")
