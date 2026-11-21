# بازبینی Gemini: پیش‌سنجش مدیر کیفیت بدون قطع تونل، نتیجه‌ی کهنه‌ی تست سایت وارد کش تازه نمی‌شه، نخ قدیمی وصل نمی‌کنه،
# مهلت‌ها با کندیِ واقعی تنظیم می‌شن، فایل ردپای خراب جای نشست سالم نمی‌شینه.
import sys, os, time, tempfile, pathlib
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W, cfgtrace as T
ORIG_AUTO_SWITCH = W._auto_switch   # بعداً برای تست‌های ۱ و ۸ با یک ثبت‌کننده عوض می‌شه

FULL = dict(yt=1, ig=1, tg=1)
def mk(raw, **kw):
    c = dict(raw=raw, host=raw, port=443, proto="vless", network="ws", security="tls", flags=set(), lat=3000, success=1.0, alive=True, sites=FULL)
    c.update(kw); return c

# ---------- ۱) مدیر کیفیت: جایگزین‌ها اول روی xray موقت سنجیده می‌شن
W.GEN[0] = 7; W.STOP.clear(); W.S["stage"] = "connected"
W.POOL.update(active=[mk("cur")], standby=[mk("a"), mk("b")], reserve=[], bad={})
W.standby_ok = lambda: W.POOL["standby"]
W.reserve_ok = lambda: []
switched = []
W._auto_switch = lambda gen, prof, c, why, verify=None: (switched.append(c["raw"]) or False)
W.auto_log = lambda *a, **k: None
W.check_many = lambda cs, *a, **k: [dict(c, alive=True, success=1.0, lat={"a": 2900, "b": 2600}[c["raw"]]) for c in cs]
W._quality_switch(7, "balanced", 3000)
assert switched == [], f"هیچ جایگزینی ≥۲۰٪ بهتر نیست؛ تونل نباید دست بخوره: {switched}"
assert "بدون قطع" in W.S["note"] and W.QUAL["cool"] > time.time() + 200
print("1a) no clearly-better replacement -> tunnel untouched OK")
W.check_many = lambda cs, *a, **k: [dict(c, alive=True, success=1.0, lat={"a": 1200, "b": 2000}[c["raw"]]) for c in cs]
W.QUAL["cool"] = 0
W._quality_switch(7, "balanced", 3000)
assert switched == ["a", "b"] or switched == ["a"], switched
assert switched[0] == "a", "بهترین (کمترین lat) اول امتحان می‌شه"
print("1b) clearly-better replacement is tried best-first OK")

# ---------- ۲) نتیجه‌ی کهنه وارد کش تازه نمی‌شه
W.SITE_CACHE.clear()
def slow_check(c, *a, **k):
    time.sleep(0.3); return dict(c, alive=True, sites=FULL, success=1.0)
W.check = slow_check
W.learn_record = lambda *a, **k: None; W.bad_clear = lambda *a, **k: None; W.bad_mark = lambda *a, **k: None
import threading
t = threading.Thread(target=lambda: W._site_probe(mk("x"), W.SITE_CACHE)); t.start()
time.sleep(0.1); W.GEN[0] += 1; t.join()
assert "x" not in W.SITE_CACHE, "جستجوی تازه شروع شده؛ نتیجه‌ی قدیمی نباید ثبت بشه"
W._site_probe(mk("y"), W.SITE_CACHE)
assert "y" in W.SITE_CACHE
print("2) stale site-probe result is dropped after a new search starts OK")

# ---------- ۳) نخ قدیمی اتصال برقرار نمی‌کنه
started = []
W.start_xray = lambda sel, prof, plain=False: (started.append(1) or sel)
W.probe_retry = lambda *a, **k: 100.0
assert W.connect_ladder([mk("z")], "balanced", 1, alive=lambda: False) is None and not started
assert W.connect_ladder([mk("z")], "balanced", 1, alive=lambda: True) is not None and started
print("3) stale connect thread does not start xray OK")

# ---------- ۴) مهلت‌ها
assert W.cand_probe_tmo(mk("q", lat=800)) == 3.0
assert 4.5 < W.cand_probe_tmo(mk("q", lat=2000)) < 5
assert W.cand_probe_tmo(mk("q", lat=6000)) == 7.0
assert W.probe_timeout_for([], seed=0) == 3.0
assert W.probe_timeout_for([None, 4200], seed=4200) == 7.0, "بدون نمونه‌ی کافی هم از پینگ لحظه‌ی اتصال شروع می‌کنه"
assert W.probe_timeout_for([900, 1000, 800, 950], seed=4200) == 3.0, "با سابقه‌ی سریع، seed نادیده گرفته می‌شه"
print("4) adaptive timeouts OK")

# ---------- ۵) چرخش: فایل خراب جای نشست سالم نمی‌شینه
W.DATA = pathlib.Path(os.environ["CFG_DATA"])
for n in ("trace_last.json", "trace_prev1.json", "trace_prev2.json"):
    (W.DATA / n).unlink(missing_ok=True)
T.reset(); T.evt("switch", "سالم"); T.incident("switch", why="c"); T.save_tail(W.DATA / "trace_prev1.json")
(W.DATA / "trace_last.json").write_text("{bad")
out = W.rotate_prev_sessions()
assert len(out) == 1 and out[0]["events"][-1][2] == "سالم"
assert (W.DATA / "trace_prev2.json").is_file() and not (W.DATA / "trace_last.json").exists()
d = T.load_prev(W.DATA / "trace_prev2.json")
assert d and d["events"][-1][2] == "سالم", "نشست سالم از بین نرفت"
print("5) corrupt trace file does not replace healthy history OK")
print("t37 OK")

# ---------- ۶) نشست خالی (باز و بسته بدون اتصال) نشست واقعی قبلی رو از تاریخچه بیرون نمی‌اندازه
for n in ("trace_last.json", "trace_prev1.json", "trace_prev2.json"):
    (W.DATA / n).unlink(missing_ok=True)
T.reset(); T.evt("switch", "واقعی"); T.incident("failover", why="x"); T.save_tail(W.DATA / "trace_last.json")
W.rotate_prev_sessions()                        # نشست واقعی ← prev1
for _ in range(3):                              # سه بار باز و بسته بدون هیچ فعالیتی
    T.reset(); T.evt("start", "فقط باز شد"); T.save_tail(W.DATA / "trace_last.json")
    out = W.rotate_prev_sessions()
assert len(out) == 1 and out[0]["events"][-1][2] == "واقعی", out
print("6) empty sessions never push real history out OK")

# ---------- ۷) مهلت سایت‌ها: جایگزین/نگهبان از SITE_TMO و پینگ تونل استفاده می‌کنن
W.SITE_TMO[0] = 5; W.S["connected"] = {"ms": 800}
assert W.site_tmo_now() == 5
W.S["connected"] = {"ms": 4200}
assert W.site_tmo_now() == 9           # 2 + 1.8*4.2 = 9.56 → 9
W.SITE_TMO[0] = 10
assert W.site_tmo_now() == 10
W.S["connected"] = None; W.SITE_TMO[0] = 5
print("7) site timeouts follow the real tunnel ping OK")

# ---------- ۸) مدیر کیفیت: سرور فعلی کامل رو هرگز با سرور ناقص (reserve) عوض نمی‌کنه
W.QUAL["cool"] = 0; switched.clear()
W.GEN[0] = 11; W.STOP.clear(); W.S["stage"] = "connected"
W.POOL.update(active=[mk("cur2")], standby=[], reserve=[mk("p", sites=dict(yt=0, ig=0, tg=1), lat=500)], sites=dict(yt=1, ig=1, tg=1))
W.standby_ok = lambda: []
W.reserve_ok = lambda: W.POOL["reserve"]
W.sites_ok = lambda c: bool((c.get("sites") or {}).get("yt") and (c.get("sites") or {}).get("ig") and (c.get("sites") or {}).get("tg"))
W.check_many = lambda cs, *a, **k: [dict(c, alive=True, success=1.0, lat=500) for c in cs]
W._quality_switch(11, "balanced", 3000)
assert switched == [], "فعلی کامل است؛ سرور ناقص نباید جایگزینش بشه"
W.POOL["sites"] = dict(yt=0, ig=0, tg=1)            # فعلی خودش ناقصه ← ناقصِ سریع‌تر قابل‌قبوله
W.QUAL["cool"] = 0
W._quality_switch(11, "balanced", 3000)
assert switched == ["p"], switched
print("8) quality switch never trades a full-sites server for a partial one OK")

# ---------- ۹) وضعیت سایت‌های فعلی ناشناخته (تازه جابه‌جا شده) ⇒ با سرور ناقص عوض نمی‌کنه
W.QUAL["cool"] = 0; switched.clear()
W.POOL.update(active=[mk("cur3", sites=None)], standby=[], reserve=[mk("p2", sites=dict(yt=0, ig=0, tg=1), lat=500)], sites=None)
W._quality_switch(11, "balanced", 3000)
assert switched == [], "وضعیت سایت‌های فعلی معلوم نیست؛ ناقص فرض نشه"
print("9) unknown current-site state is not treated as incomplete OK")

# ---------- ۱۰) _auto_switch: مهلت پرابِ تأیید با پینگ جایگزین هماهنگه
seen = []
W.probe_retry = lambda n=3, timeout=3: (seen.append(timeout) or 100.0)
W.start_xray = lambda sel, prof, plain=False: sel
W.set_active = lambda sel, ms=None: None; W.save_good = lambda s: None; W.sw_mark = lambda r: None
W.MODE[0] = "stable"; W.S["stage"] = "connected"; W.GEN[0] = 12
W.POOL.update(active=[mk("cur4")], standby=[], switches=0)
W._auto_switch = ORIG_AUTO_SWITCH
assert W._auto_switch(12, "balanced", mk("slow", lat=4000), "t") is True
assert seen[0] > 3.0, seen
print("10) _auto_switch confirm-probe timeout follows candidate latency OK")

# ---------- ۱۱) بعد از جابه‌جایی: سرور فعال از پناهگاه (reserve) حذف می‌شه و وضعیت سایت‌هاش خالی نمی‌مونه
W.start_xray = lambda sel, prof, plain=False: sel
W.probe_retry = lambda n=3, timeout=3: 100.0
W.set_active = lambda sel, ms=None: None; W.save_good = lambda s: None; W.sw_mark = lambda r: None
W.MODE[0] = "stable"; W.S["stage"] = "connected"; W.GEN[0] = 13; W.STOP.clear()
nb = mk("newbest", sites=dict(yt=0, ig=0, tg=1), lat=900)
W.POOL.update(active=[mk("old5")], standby=[], reserve=[nb, mk("other")], switches=0, sites=None)
assert W._auto_switch(13, "balanced", nb, "t") is True
assert [c["raw"] for c in W.POOL["reserve"]] == ["other"], W.POOL["reserve"]
assert W.POOL["sites"] == dict(yt=0, ig=0, tg=1), W.POOL["sites"]
print("11) active server leaves reserve; site state kept after switch OK")
