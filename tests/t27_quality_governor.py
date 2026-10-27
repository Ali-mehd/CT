"""مدیر کیفیت: «وصل ولی کند» ← امتحان جایگزین‌ها با پینگ واقعی؛ سقف مصرف نگهداری حداقلی رو نمی‌بنده؛ انتخاب صریح کاربر برای سقف."""
import sys, os, tempfile, time, threading, types
d0 = tempfile.mkdtemp(); os.environ["CFG_DATA"] = d0; sys.path.insert(0, ".")
import cfgweb as W, cfgdata as D

def mk(h, **kw):
    c = {"host": h, "port": 443, "proto": "vless", "network": "ws", "security": "tls", "flow": "", "raw": f"vless://{h}:443", "ip": "",
         "alive": True, "flags": set(), "success": 1.0, "lat": 100, "sites": dict(yt=1, ig=1, tg=1), "site_t": time.time(), "verified_at": time.time()}
    c.update(kw); return c

# ۱) _quality_switch واقعی: اولین جایگزین در عمل بهتر نیست ← برمی‌گرده؛ دومی بهتره ← می‌مونه
def setup():
    W.GEN[0] += 1; W.STOP.clear(); W.MODE[0] = "stable"; W.CUR[0] = "auto"; W.S.update(stage="connected", note="")
    act = mk("60.0.0.1"); W.POOL.update(active=[act], standby=[mk("60.0.0.2"), mk("60.0.0.3"), mk("60.0.0.4")], bench=[], switches=0)
    W.HOLD_UNTIL[0] = 0; W.QUAL["cool"] = 0
    real = {"60.0.0.1": 3000, "60.0.0.2": 2900, "60.0.0.3": 400, "60.0.0.4": 350}   # پینگ واقعیِ هر سرور
    cur = ["60.0.0.1"]; log = []
    def sx(sel, profile, plain=False): cur[0] = sel[0]["host"]; log.append(cur[0]); return sel
    W.start_xray = sx
    W.probe_retry = lambda *a, **k: float(real[cur[0]]); W.probe = lambda t=3.0: float(real[cur[0]])
    W.set_active = lambda sel, ms=None: W.POOL.update(active=list(sel))
    W.save_good = lambda sel: None; W.sw_mark = lambda r: None
    W.sites_ok = lambda c: True; W.standby_ok = lambda: list(W.POOL["standby"]); W.flaky = lambda c: 0; W.eff = lambda c: c["lat"]
    # ترتیب امتحان رو با lat تعیین کن (کمترین اول)
    for i, c in enumerate(W.POOL["standby"]): c["lat"] = 100 + i
    return act, log
act, log = setup()
W._quality_switch(W.GEN[0], "auto", 3000)
assert log == ["60.0.0.2", "60.0.0.1", "60.0.0.3"], log             # ۲ بهتر نبود ← برگشت به ۱؛ ۳ بهتر بود ← موند
assert W.POOL["active"][0]["host"] == "60.0.0.3" and any(c["host"] == "60.0.0.1" for c in W.POOL["standby"])
assert W.QUAL["cool"] > time.time() and "بهتر" in W.S["note"]
act, log = setup()
for c in W.POOL["standby"]: pass
W.probe_retry = lambda *a, **k: 2900.0; W.probe = lambda t=3.0: 2900.0   # هیچ‌کدوم بهتر نیست
W._quality_switch(W.GEN[0], "auto", 3000)
assert W.POOL["active"][0]["host"] == "60.0.0.1" and "بهتر نبودن" in W.S["note"] and W.POOL.get("refill_fast", 0) > time.time()
act, log = setup(); W.POOL["standby"] = []
W._quality_switch(W.GEN[0], "auto", 3000)
assert not log and "جایگزین تأییدشده‌ای ندارم" in W.S["note"]
act, log = setup(); W.MODE[0] = "off"
W._quality_switch(W.GEN[0], "auto", 3000)
assert W.POOL["active"][0] is act and W.POOL["active"][0]["host"] == "60.0.0.1"   # قفل سرور
print("1) quality switch: tries replacements by REAL ping, reverts if not better, respects lock / no-candidate cases OK")

# ۲) ناظر با ساعت شبیه‌سازی‌شده: کندیِ پیوسته ← بعد از ~۳۰ ثانیه یک بار؛ پینگ خوب یا کار حساس/تماس/انتقال ← هرگز
class FakeTime:
    def __init__(s): s.t = 1_800_000_000.0
    def time(s): return s.t
    def sleep(s, x): s.t += max(x, 0.01); time.sleep(0)
    def __getattr__(s, k): return getattr(time, k)
def run_sup(act_name, ms, seconds=240, mode="stable", call=False):
    setup(); W.ACT.reset(); W.APIPORT[0] = 1; W.CALL[0] = call
    ft = FakeTime(); W.time = ft; W.ACT.tracker.act = act_name
    W.probe_robust = lambda *a, **k: float(ms); W.probe = lambda *a, **k: float(ms)
    W.net_up = lambda: True; W.calm_ok = lambda: True; W.server_cut_confirmed = lambda: False
    W.refresh_standby = lambda gen: None; W.upgrade_check = lambda *a: None; W.failover = lambda *a, **k: None
    W.XRAY_PROC = types.SimpleNamespace(poll=lambda: None); W.RUNNING[0] = 0
    calls = []; W._quality_switch = lambda gen, p, med: calls.append(med)
    g = W.GEN[0]
    th = threading.Thread(target=W.supervisor, args=(g, "auto", True, mode), daemon=True); th.start()
    t0 = ft.t
    for _ in range(600):
        time.sleep(0.003)
        if ft.t - t0 > seconds: break
    W.GEN[0] += 1; th.join(2); W.time = time; W.CALL[0] = False
    return calls
assert len(run_sup("normal", 3000)) >= 1      # (در برنامه‌ی واقعی بعد از هر تلاش ۳ تا ۵ دقیقه صبر می‌کنه؛ اینجا شبیه‌ساز فقط ۹۰ ثانیه)
assert len(run_sup("interactive", 2500)) >= 1
assert run_sup("normal", 600) == []                                                   # پینگ قابل‌قبوله
assert run_sup("call", 3000) == [] and run_sup("secure", 3000) == []                  # وسط تماس/کار حساس
assert run_sup("upload", 3000) == [] and run_sup("download", 3000) == []              # وسط انتقال حجیم، پینگ از خودِ انتقال باد می‌کنه
assert run_sup("normal", 3000, call=True) == []                                       # حالت تماس دستی
print("2) governor trigger: sustained slow link -> one switch attempt; fine ping / call / secure / bulk transfer / call-mode -> never OK")

# ۳) سقف مصرف: نگهداری حداقلی بسته نمی‌شه؛ فقط کارهای پرمصرف
W.load_settings = lambda: {"data_mb": 1, "data_mb_user": True}; W.net_is_mobile = lambda: False
D.DAY.clear(); D.add(5_000_000)
assert W.data_saver() and not W.bg_quiet() and W.heavy_quiet()
print("3) budget exhausted: heavy work stops, minimal maintenance stays on OK")

# ۴) مقدارِ ذخیره‌شده‌ی بدون انتخاب صریحِ کاربر نادیده گرفته می‌شه (باگِ ۱۵۰ مگابایتِ ناخواسته روی دسکتاپ)
W.load_settings = lambda: {"data_mb": 150}
assert W.data_budget_mb() == 0
W.net_is_mobile = lambda: True
assert W.data_budget_mb() == 150
W.net_is_mobile = lambda: False
W.load_settings = lambda: {"data_mb": 400, "data_mb_user": True}
assert W.data_budget_mb() == 400
# ذخیره‌ی واقعی
W.SETTINGS = type(W.SETTINGS)(d0) / "settings.json"
W.load_settings = W.__dict__["load_settings"]
print("4) stored budget without explicit user choice is ignored; explicit choice honored OK")
print("ALL OK")
