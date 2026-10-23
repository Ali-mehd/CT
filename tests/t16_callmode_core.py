"""حالت تماس در هسته: روشن/خاموش و ماندگاری، رتبه‌بندی، انتخاب سرور با بازگشت خودکار، ساکت‌شدن کارهای پس‌زمینه، کانفیگ xray."""
import sys, os, tempfile, json, time, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W, cfgcall as C, cfgforge as F, cfgscan

def mk(h, **kw):
    c = {"host": h, "port": 443, "proto": "vless", "network": "ws", "security": "tls", "flow": "", "raw": f"vless://{h}:443",
         "alive": True, "flags": set(), "success": 1.0, "lat": 100, "sites": dict(yt=1, ig=1, tg=1), "site_t": time.time(), "verified_at": time.time()}
    c.update(kw); return c
def q(grade_loss=0, p50=40, jitter=3):
    rt = [p50 + (jitter if i % 2 else 0) if i >= grade_loss else None for i in range(20)]
    return C.assess(rt)

# ---- ۱) روشن/خاموش و همگام‌بودن پرچم کانفیگ‌ساز
assert W.CALL[0] is False and F.CALL[0] is False
W.set_call(True); assert W.CALL[0] and F.CALL[0]
W.S["call"] = q(); st = W.call_state()
assert st["on"] and st["q"]["grade"] in ("excellent", "good") and st["tg"].startswith("tg://socks?server=127.0.0.1&port=") and st["tips"] == []
W.set_call(False); assert not W.CALL[0] and not F.CALL[0] and W.S["call"] is None and W.call_state()["q"] is None
print("1) toggle keeps cfgweb/cfgforge flags in sync, state exposes quality + Telegram SOCKS5 link OK")

# ---- ۲) ماندگاری در settings.json و بارگذاری
W.save_settings({"call": True}); assert json.loads(W.SETTINGS.read_text(encoding="utf-8"))["call"] is True
W.save_settings({"call": False}); assert json.loads(W.SETTINGS.read_text(encoding="utf-8"))["call"] is False
W.save_settings({"call": "yes"}); assert json.loads(W.SETTINGS.read_text(encoding="utf-8"))["call"] is False, "غیر بولین نادیده گرفته می‌شه"
print("2) setting persists; non-boolean input ignored OK")

# ---- ۳) رتبه‌بندی: اول UDP-دار با MOS بالاتر؛ بدون اندازه‌گیری بعد از اندازه‌گیری‌شده‌ی قابل‌قبول؛ UDP-نداره آخر
W.set_call(True)
a = mk("1.1.1.1", call=q(), lat=300); b = mk("2.2.2.2", call=q(p50=120, jitter=30), lat=50); n = mk("3.3.3.3", lat=10)
d = mk("4.4.4.4", call=C.assess([None] * 20), lat=5); p = mk("5.5.5.5", call=q(grade_loss=9), lat=5)
order = sorted([d, n, p, b, a], key=W.rk)
assert order[0] is a and order[1] is b, [x["host"] for x in order]
assert order[-1] is d or order[-2] is d, "بدون UDP"
assert W.rk(a)[0] == 0 and W.rk(d)[0] == 1 and W.rk(n)[0] == 1
W.set_call(False); assert W.rk(a) != W.call_key(a) + (W.eff(a),), "خارج از حالت تماس رتبه‌ی عادیه"
print("2b) call ranking: good UDP first (by MOS), unmeasured after, no-UDP last OK")

# ---- ۴) کانفیگ xray: یک خروجی ثابت، بدون mux/sniffing/balancer، با policy (و حالت عادی بدون تغییر)
cfgs = [dict(cfgscan.parse(l)) for l in [
    "vless://dc2259c4-388e-4285-ba18-df619b6672b6@82.118.16.187:443?security=reality&type=tcp&sni=www.cloudflare.com&fp=chrome&flow=xtls-rprx-vision&sid=cd60&pbk=R5ycsjJ-v024902dMSqTsSdqxUwCFEXMebdBEWFt9VU#a",
    "vless://7967bf59-57e3-4cde-9898-527b0fe60022@45.80.111.7:8443?security=tls&type=ws&path=/x&host=a.example.com&sni=a.example.com&fp=chrome&encryption=none#b",
    "vless://7967bf59-57e3-4cde-9898-527b0fe60023@45.80.111.8:8443?security=tls&type=ws&path=/x&host=b.example.com&sni=b.example.com&fp=chrome&encryption=none#c"]]
F.CALL[0] = False; n_cfg, n_sel = F.make_client(cfgs, "balanced", None, [], 1, 2)
assert len(n_sel) == 3 and "policy" not in n_cfg and n_cfg["inbounds"][0]["sniffing"]["enabled"] and "balancers" in n_cfg["routing"]
F.CALL[0] = True;  c_cfg, c_sel = F.make_client(cfgs, "balanced", None, [], 1, 2)
assert len(c_sel) == 1 and c_cfg["policy"]["levels"]["0"]["connIdle"] == 600 and not c_cfg["inbounds"][0]["sniffing"]["enabled"]
assert "balancers" not in c_cfg["routing"] and not any("mux" in o for o in c_cfg["outbounds"]), "balancer/mux در حالت تماس نباید باشه"
assert c_cfg["inbounds"][0]["settings"]["udp"] is True
F.CALL[0] = False
print("4) call-mode xray config: single outbound, no balancer/mux/sniffing, UDP on, idle timeout 600s; normal mode unchanged OK")

# ---- ۵) پس‌زمینه ساکت می‌شه: refill، bench، standby_sites، sites_watch در حالت تماس کاری نمی‌کنن
W.set_call(True); W.GEN[0] += 1; gen = W.GEN[0]
W.S.update(stage="connected"); W.POOL.update(active=[mk("9.9.9.9")], standby=[], backlog=[mk("8.8.8.1"), mk("8.8.8.2")], bench=[mk("7.7.7.7", next_t=0)])
hits = []
W.check_many = lambda *a, **k: (hits.append(1), [])[1]
W.check = lambda *a, **k: (hits.append(1), {})[1]
real_sleep = time.sleep; W.time.sleep = lambda x: real_sleep(0.01)
threads = [threading.Thread(target=W.refill, args=(gen, "balanced", set()), daemon=True), threading.Thread(target=W.bench_loop, args=(gen,), daemon=True),
           threading.Thread(target=W.standby_sites, args=(gen,), daemon=True)]
for t in threads: t.start()
real_sleep(0.6); W.GEN[0] += 1; real_sleep(0.3)
W.time.sleep = real_sleep
assert not hits and len(W.POOL["backlog"]) == 2, (len(hits), len(W.POOL["backlog"]))
print("5) call mode silences refill / bench / standby-sites (no tests, no backlog consumption) OK")

# ---- ۶) call_prepare: سرور فعلی خوبه → عوض نمی‌شه؛ بدتره و جایگزین واضحاً بهتره → عوض می‌شه؛ جایگزین بدتر از آب درآد → برمی‌گرده
def setup(cur_q, cand_q):
    W.CALL_MAX_RETRIES = 0
    W.set_call(True); W.GEN[0] += 1
    W.S.update(stage="connected", note="", warn="")
    act = mk("10.0.0.9"); best = mk("11.1.1.1", raw="vless://best:443")
    W.POOL.update(active=[act], standby=[best], bench=[], switches=0)
    seq = iter(cur_q)
    W.cfgcall.measure_via = lambda port, n=12: next(seq)
    W.check_many = lambda cs, *a, **k: [dict(c, call=cand_q) if cand_q else dict(c) for c in cs]
    calls = []
    W.start_xray = lambda sel, profile, plain=False: (calls.append(sel[0]["host"]), sel)[1]
    W.probe_retry = lambda *a, **k: 80.0
    W.set_active = lambda sel, ms=None: W.POOL.update(active=list(sel))
    W.save_good = lambda sel: None; W.sw_mark = lambda r: None
    return act, best, calls
good_q, poor_q = q(), q(grade_loss=6)
# الف) فعلی خوب است
act, best, calls = setup([good_q], q()); W.call_prepare(W.GEN[0], "balanced", True)
assert not calls and W.POOL["active"][0] is act and ("خوب" in W.S["note"] or "عالی" in W.S["note"]), (calls, W.S["note"])
# ب) فعلی ضعیف، جایگزین عالی → سوییچ (دومین اندازه‌گیری بعد از سوییچ هم خوبه)
act, best, calls = setup([poor_q, good_q], good_q); W.call_prepare(W.GEN[0], "balanced", True)
assert calls == ["11.1.1.1"] and W.POOL["active"][0]["host"] == "11.1.1.1" and any(x["host"] == "10.0.0.9" for x in W.POOL["standby"]) and W.POOL["switches"] == 1, (calls, W.S["note"])
# ج) فعلی ضعیف، جایگزین عالی ولی بعد از سوییچ بدتر از آب درآد → برگشت به قبلی
act, best, calls = setup([poor_q, poor_q], good_q); W.call_prepare(W.GEN[0], "balanced", True)
assert calls == ["11.1.1.1", "10.0.0.9"] and W.POOL["switches"] == 0 and "پیدا نشد" in W.S["note"], (calls, W.S["note"])
# د) switch=False → فقط اندازه می‌گیره
act, best, calls = setup([poor_q], good_q); W.call_prepare(W.GEN[0], "balanced", False); assert not calls
# هـ) جایگزین بدون UDP یا ضعیف → هرگز انتخاب نمی‌شه
for bad in (C.assess([None] * 20), q(grade_loss=8), None):
    act, best, calls = setup([poor_q], bad); W.call_prepare(W.GEN[0], "balanced", True); assert not calls, bad
# و) خاموش‌شدن حالت تماس وسط کار → هیچ سوییچی نمی‌شه
act, best, calls = setup([poor_q], good_q); W.cfgcall.measure_via = lambda port, n=12: (W.set_call(False), poor_q)[1]; W.call_prepare(W.GEN[0], "balanced", True); assert not calls
print("6) call_prepare: keeps a good server, switches only for a clearly better one, reverts when the new one is worse, never picks no-UDP/weak OK")
print("ALL OK")
