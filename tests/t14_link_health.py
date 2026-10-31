"""سلامت لینک فعال: قطعِ کامل در برابر نوسان، سرور کنارگذاشته‌شده، ماندن روی سرور فعلی، قرنطینه‌ی جدا برای هر شبکه."""
import sys, os, tempfile, time, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W
W.learn_reset()

def mk(host, port=443, proto="vless", **kw):
    c = {"host": host, "port": port, "proto": proto, "network": "ws", "security": "tls", "raw": f"{proto}://{host}:{port}",
         "alive": True, "flags": set(), "success": 1.0, "lat": 100, "ip": host if host[0].isdigit() else "93.184.216.34"}
    c.update(kw); return c

# ---------- ۱) دسته‌بندی وضعیت لینک
LS = W.link_state
assert LS([100] * 10 + [None] * 3, 3) == "cut"
assert LS([100] * 10 + [None, None], 2) != "cut", "دو خطای پشت‌سرهم قطع کامل نیست"
assert LS([100] * 5 + [None, 100, None, 100, 100, None, 100], 1) == "jittery"  # ۳ از ۱۲ بی‌جواب (۲۵٪)
assert LS([100, None] * 6, 1) == "lossy"
assert LS([100] * 3, 0) == "good" and LS([100, None, None], 2) == "good", "کمتر از ۶ نمونه: قضاوت نمی‌کنه"
assert LS([60, 70, 65, 62, 1500, 1800, 66, 64, 63, 1700, 61, 60], 0) == "jittery"
assert LS([60, 70, 65, 62, 66, 64, 63, 68, 61, 60, 59, 71], 0) == "good"
assert LS([60, 70, 65, 62, 66, 64, 63, 68, 61, 60, 59, 71] + [None] * 3, 3) == "cut"
print("1) link_state: cut / lossy / jittery / good, no verdict on <6 samples OK")

# ---------- ۲) قطعِ کامل ثابت‌شده فقط وقتی اینترنت خودت وصله و سرور واقعاً جواب نمی‌ده
real_cc, real_net_up = W.socket.create_connection, W.net_up
class Sock:
    def close(self): pass
def run(accept, net):
    W.socket.create_connection = (lambda *a, **k: Sock()) if accept else (lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    W.net_up = lambda: net
    try: return W.server_cut_confirmed()
    finally: W.socket.create_connection, W.net_up = real_cc, real_net_up
W.POOL["active"] = [mk("1.1.1.1")]
assert run(accept=False, net=True) is True
assert run(accept=True, net=True) is False, "سرور جواب می‌ده: مشکل مسیره، نه قطعی سرور"
assert run(accept=False, net=False) is False, "اینترنت خودت قطعه: سرور مقصر نیست"
W.POOL["active"] = [mk("2.2.2.2", proto="hysteria2")]
assert run(accept=False, net=True) is False, "UDP: TCP معنی نداره"
# فقط IP تأییدشده؛ بدون IP یا با IP داخلی، هیچ اتصالی زده نمی‌شه و جواب False می‌ده
hit = []; W.socket.create_connection = lambda *a, **k: (hit.append(a[0]), (_ for _ in ()).throw(OSError("x")))[1]; W.net_up = lambda: True
for ip in (None, "", "10.0.0.5", "127.0.0.1", "not-an-ip"):
    W.POOL["active"] = [mk("evil.example", ip=ip)]; assert W.server_cut_confirmed() is False, ip
assert not hit, hit
W.POOL["active"] = [mk("evil.example", ip="93.184.216.34")]; assert W.server_cut_confirmed() is True and hit[0][0] == "93.184.216.34", hit
W.socket.create_connection, W.net_up = real_cc, real_net_up
print("2) cut confirmed only with own-internet control up AND server refusing TCP twice; only the verified public IP is contacted OK")

# ---------- ۳) سرور کنارگذاشته‌شده: بازبینی زود، دو بار سالم برای برگشت، چهار شکست برای حذف
now = [10_000.0]; real_time = time.time; time.time = lambda: now[0]
def fresh_pool(): W.POOL.update(active=[mk("9.9.9.9")], standby=[], bench=[], bad={})
def res(c, ok=True, sites=True):
    r = dict(c); r.update(alive=ok, success=1.0 if ok else 0.0, sites=dict(yt=sites, ig=sites, tg=sites)); return r
state = {"ok": True, "sites": True, "n": 0}
def fake_check(cs, *a, **k):
    state["n"] += 1; return [res(c, state["ok"], state["sites"]) for c in cs]
W.check_many = fake_check
fresh_pool(); c = mk("3.3.3.3"); W.bench_add([c]); assert c["next_t"] == now[0] + 20
now[0] += 10; assert W.bench_step() == [] and state["n"] == 0, "قبل از ۲۰ ثانیه سنجیده نمی‌شه"
now[0] += 11; assert W.bench_step() and state["n"] == 1 and c["ok_run"] == 1 and not W.POOL["standby"], "یک بار سالم کافی نیست"
now[0] += 26; W.bench_step()
assert [x["raw"] for x in W.POOL["standby"]] == [c["raw"]] and not W.POOL["bench"] and W.flaky(c), "دو بار سالم → برمی‌گرده، با نشانه‌ی ناپایدار"
print("3a) benched server: first recheck at 20s, back after 2 good checks, marked flaky OK")
# سالم، بعد ناسالم → شمارنده‌ی «سالم پشت‌سرهم» صفر می‌شه
fresh_pool(); c = mk("3.3.3.4"); W.bench_add([c]); state.update(ok=True, sites=True)
now[0] += 21; W.bench_step(); assert c["ok_run"] == 1
state["ok"] = False; now[0] += 26; W.bench_step(); assert c["ok_run"] == 0 and c["bench_fail"] == 1 and not W.POOL["standby"]
# چهار شکست → کنار گذاشته می‌شه؛ فاصله‌ها ۶۰/۱۸۰/۴۲۰
for i, gap in enumerate((60, 180, 420)):
    assert c["next_t"] == now[0] + gap, (i, c["next_t"] - now[0]); now[0] += gap + 1; W.bench_step()
assert not W.POOL["bench"] and not W.POOL["standby"]
print("3b) four failed rechecks (20/60/180/420s) -> dropped; a good check followed by a bad one resets the streak OK")
# سالم ولی سایت‌ها بسته → برنمی‌گرده
fresh_pool(); c = mk("3.3.3.5"); W.bench_add([c]); state.update(ok=True, sites=False)
for _ in range(2): now[0] += 500; W.bench_step()
assert not W.POOL["standby"]; print("3c) alive but sites closed -> does not return OK")
# خطرناک هرگز وارد نیمکت نمی‌شه
fresh_pool(); d = mk("3.3.3.6", flags={"tls_verify_fail"}); W.bench_add([d]); assert not W.POOL["bench"]
# سرور ناپایدار آخر صفِ جایگزین‌هاست
fresh_pool(); a, b = mk("4.4.4.1", lat=300), mk("4.4.4.2", lat=100, flaky_until=now[0] + 600)
for x in (a, b): x.update(sites=dict(yt=1, ig=1, tg=1), verified_at=now[0])
rest = sorted([b, a], key=lambda c: (not W.sites_ok(c), W.flaky(c), c.get("verified_at", 0) < now[0] - 90, -(c.get("success") or 0), W.eff(c)))
assert rest[0] is a; now[0] += 1900; assert not W.flaky(b)
print("3d) dangerous never benched; flaky server ranks after a clean one for 30 minutes then recovers rank OK")
time.time = real_time

# ---------- ۴) جایگزین نداریم: اگه سرور فعلی هنوز (ضعیف) جواب می‌ده همون‌جا می‌مونیم و پس‌زمینه می‌گردیم
calls = []; W.pipeline = lambda *a, **k: calls.append(a)
fresh_pool(); W.POOL["standby"] = []; act = W.POOL["active"][0]
W.probe = lambda *a, **k: 480.0
W._failover(W.GEN[0], "balanced", False, "stable"); time.sleep(0.2)
assert not calls and not W.POOL["bench"] and not W.POOL["bad"] and act.get("strikes", 0) == 0, "نباید سرور فعلی بد حساب بشه یا اسکن تازه قطعش کنه"
assert W.POOL["refill_fast"] > time.time() and "وصل موندم" in W.S["note"]
print("4a) no replacement + server still answering -> stay connected, refill speeds up, no restart, no strike OK")
W.probe = lambda *a, **k: None   # تونل کاملاً مرده
fresh_pool(); W.POOL["standby"] = []
r4 = W._failover(W.GEN[0], "balanced", False, "stable"); time.sleep(0.3)
assert r4 == "restart" and W.POOL["bench"], "تونل مرده: اسکن تازه (از مسیر ثبت‌شده‌ی restart_pipeline) شروع می‌شه و سرور برای بازبینی کنار می‌ره"
print("4b) no replacement + tunnel dead -> new scan starts, old server benched for rechecks OK")

# ---------- ۵) قرنطینه «به‌تفکیک شبکه»: مرده روی مودم ≠ مرده روی نت همراه؛ خطرناک سراسریه
W.BAD["h"].clear(); s = mk("5.5.5.5")
W.NETID[0] = "a:modem"; W.bad_mark(s, "dead"); W.bad_mark(s, "dead")
assert sum(W.bad_skip(s) for _ in range(500)) > 400
W.NETID[0] = "a:mobile"; assert not any(W.bad_skip(s) for _ in range(500)), "روی نت همراه قرنطینه نیست"
W.bad_mark(s, "dead"); W.bad_clear(s, "dead")
W.NETID[0] = "a:modem"; assert sum(W.bad_skip(s) for _ in range(500)) > 400, "پاک‌شدن روی نت همراه، مودم رو آزاد نمی‌کنه"
dg = mk("6.6.6.6"); W.NETID[0] = "a:modem"; W.bad_mark(dg, "danger")
for n in ("a:modem", "a:mobile", ""): 
    W.NETID[0] = n; assert all(W.bad_skip(dg) for _ in range(200)), n
W.NETID[0] = ""
print("5) dead/sites quarantine is per network, danger quarantine is global OK")

# ---------- ۶) حلقه‌ی supervisor با پینگ‌های سناریویی
def run_sup(pings, tcp_accept, standby=True, mode="stable"):
    W.POOL.update(active=[mk("7.7.7.7")], standby=[mk("8.8.8.8")] if standby else [], bench=[], bad={})
    W.S.update(stage="connected", connected={"ms": 1}, warn="", note=""); W.RUNNING[0] = 0
    it = iter(pings); seen = []
    class P:  # xray زنده
        def poll(self): return None
    W.XRAY_PROC = P()
    def pr(t=3.0):
        try: return next(it)
        except StopIteration: W.S["stage"] = "idle"; return 50.0
    W.probe_robust = pr; W.probe = pr
    W.net_up = lambda: True
    W.socket.create_connection = (lambda *a, **k: Sock()) if tcp_accept else (lambda *a, **k: (_ for _ in ()).throw(OSError("x")))
    def fo(*a, **k): seen.append(len(seen) + 1); W.S["stage"] = "idle"
    W.failover = fo
    rs = W.time.sleep; W.time.sleep = lambda x: None
    try: W.supervisor(W.GEN[0], "balanced", False, mode)
    finally: W.time.sleep = rs; W.socket.create_connection = real_cc
    return seen
base = [60] * 12
assert run_sup(base + [None] * 3 + [60] * 5, tcp_accept=False), "قطعِ کامل + سرور جواب نمی‌ده → بعد از ۳ خطا"
assert not run_sup(base + [None, None, 60] + [60] * 8, tcp_accept=False), "دو خطای لحظه‌ای فقط یک پرش‌ه"
assert not run_sup(base + [None] * 3 + [60] * 8, tcp_accept=True), "سرور TCP جواب می‌ده: سه خطا قطعِ کامل ثابت نمی‌کنه"
assert run_sup(base + [None] * 5 + [60] * 5, tcp_accept=True), "ولی پنج خطای پشت‌سرهم همچنان جابه‌جایی می‌ده"
print("6a) supervisor: confirmed cut -> switch after 3 failures; blips and path problems wait for 5 OK")
jit = [60, 70, 65, 1500, 62, 1800, 64, 66, 1600, 61, 60, 63]
seen = run_sup(jit + [60] * 2, tcp_accept=True); assert not seen, "نوسان تنها جابه‌جایی نمی‌ده"
assert "نوسان" in W.S["warn"], W.S["warn"]
W.S["stage"] = "connected"
print("6b) high jitter alone never triggers a switch OK")
print("ALL OK")
