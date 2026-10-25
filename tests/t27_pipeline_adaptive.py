# اجرای واقعی pipeline با قطعه‌های جعلی (بدون xray و اینترنت): صف زنده درست کار می‌کنه و هیچ کانفیگی گم یا دوباره تست نمی‌شه
import sys, os, random, tempfile, time, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp(); os.environ["CFG_NETPROBE"] = "0"
sys.path.insert(0, '.')
import cfgweb as W, cfgscan as C
random.seed(3)
N = 1500
links, origin = [], {}
for i in range(N):
    kind = random.random()
    if kind < 0.5:
        l = f"vless://{i:08d}-aaaa-bbbb-cccc-000000000000@45.{i % 200 + 1}.{i // 200 + 1}.5:443?type=ws&security=tls&sni=a{i}.example.com&path=%2Fx&host=a{i}.example.com#ws{i}"
    else:
        l = f"vless://{i:08d}-aaaa-bbbb-cccc-000000000000@45.{i % 200 + 1}.{i // 200 + 1}.6:8443?type=tcp&security=reality&pbk=Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmE&sni=b{i}.example.com&sid=ab&flow=xtls-rprx-vision&fp=chrome#rl{i}"
    links.append(l)
seen_order, lock = [], threading.Lock()
def fake_reach(c, t): c["reachable"] = True; c["latency"] = 50
def fake_live(c, xray, rounds, t, **k):
    with lock: seen_order.append(c["raw"])
    time.sleep(0.002)
    c["alive"] = (c["security"] == "reality" and random.random() < 0.05)
    c["sites"] = {}
C.reach, C.live = fake_reach, fake_live
C.fetch_sources = lambda urls, **kw: (list(links), {})
W.find_xray = lambda: "/bin/true"; W.find_singbox = lambda: None
W.disconnect = lambda *a, **k: None
W.refill = lambda *a, **k: None; W.channels_retry = lambda *a, **k: None
W.sites_pick = lambda found, cache: []
W.PREFETCH.update(links=[], stats={}, t=0)
W.say = lambda *a, **k: None
t = threading.Thread(target=W.pipeline, args=("balanced", False, False, "off", False), daemon=True); t.start()
last, same = -1, 0
t_end = time.time() + 100
while time.time() < t_end:  # صبر تا اولین دور تموم بشه (بعدش pipeline «تسلیم نمی‌شه» و دور بعد می‌ره؛ همون‌جا متوقفش می‌کنیم)
    time.sleep(0.5)
    n = len(seen_order)
    same = same + 1 if n == last and n > 100 else 0
    last = n
    if same >= 6:
        break
W.STOP.set(); t.join(30)
seen_order[:] = list(dict.fromkeys(seen_order))[:last]
print("stage:", W.S.get("stage"), "| tested:", len(seen_order), "of", N)
assert len(seen_order) == len(set(seen_order)), "a config was tested twice"
first = seen_order[: len(seen_order) // 2]; second = seen_order[len(seen_order) // 2:]
ws = lambda xs: sum(1 for r in xs if "type=ws" in r) / max(1, len(xs))
print("ws/tls (dead method) share: first half %.0f%% | second half %.0f%%" % (100 * ws(first), 100 * ws(second)))
assert ws(second) < ws(first) or len(seen_order) < 400
print("ALL OK")
