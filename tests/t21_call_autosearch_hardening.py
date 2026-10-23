"""جستجوی خودکار سرور مناسب تماس + سخت‌کردن‌های متناسب (قفل تک‌نمونه‌ای، schema منابع، ناظر مقاوم، شروع/پاک‌سازی)."""
import sys, os, tempfile, json, time, threading
os.environ["CFG_DATA"] = tempfile.mkdtemp(); sys.path.insert(0, ".")
import cfgweb as W, cfgcall as C

def mk(h, **kw):
    c = {"host": h, "port": 443, "proto": "vless", "network": "ws", "security": "tls", "flow": "", "raw": f"vless://{h}:443",
         "alive": True, "flags": set(), "success": 1.0, "lat": 100, "sites": dict(yt=1, ig=1, tg=1), "site_t": time.time(), "verified_at": time.time()}
    c.update(kw); return c
def q(loss=0, p50=40, jitter=3):
    return C.assess([p50 + (jitter if i % 2 else 0) if i >= loss else None for i in range(20)])
poor, good = q(loss=6), q()

def setup(cur_seq, measure):
    """measure(c) -> کیفیت تماس هر کاندید (None = بدون نتیجه)"""
    W.CALL_MAX_RETRIES, W.CALL_RETRY_SECS = 0, 0
    W.set_call(True); W.GEN[0] += 1; W.STOP.clear(); W.S.update(stage="connected", note="")
    act = mk("10.0.0.9")
    W.POOL.update(active=[act], standby=[], bench=[], switches=0)
    seq = iter(cur_seq); last = [cur_seq[-1]]
    def mv(port, n=12):
        try: last[0] = next(seq)
        except StopIteration: pass
        return last[0]
    W.cfgcall.measure_via = mv
    checked = []
    def cm(cs, *a, **k):
        checked.append([c["host"] for c in cs])
        return [dict(c, call=measure(c)) if measure(c) else dict(c) for c in cs]
    W.check_many = cm
    calls = []
    W.start_xray = lambda sel, profile, plain=False: (calls.append(sel[0]["host"]), sel)[1]
    W.probe_retry = lambda *a, **k: 80.0
    W.set_active = lambda sel, ms=None: W.POOL.update(active=list(sel))
    W.save_good = lambda sel: None; W.sw_mark = lambda r: None
    return act, calls, checked

# ۱) جستجوی چنددوری: دسته‌ی اول (۶ تا) همه بد، دسته‌ی دوم یکی خوب دارد → پیدا و سوییچ می‌شه (کاربر هیچ کاری نمی‌کنه)
act, calls, checked = setup([poor, good], lambda c: good if c["host"] == "20.0.0.9" else poor)
W.POOL["standby"] = [mk(f"20.0.0.{i}") for i in range(1, 12)]
W.call_prepare(W.GEN[0], "balanced", True)
assert len(checked) == 2 and calls == ["20.0.0.9"] and W.POOL["active"][0]["host"] == "20.0.0.9", (checked, calls, W.S["note"])
print("1) multi-round search finds the good server in the 2nd batch and switches by itself OK")

# ۲) هیچ سروری UDP نداره (STUN روی شبکه بسته) → «بد» حساب نمی‌شه، سوییچ نمی‌شه، پیام درست
noudp = C.assess([None] * 20)
act, calls, checked = setup([noudp], lambda c: noudp)
W.POOL["standby"] = [mk(f"21.0.0.{i}") for i in range(1, 4)]
W.call_prepare(W.GEN[0], "balanced", True)
assert not calls and "STUN" in W.S["note"] and W.POOL["active"][0] is act, (calls, W.S["note"])
print("2) UDP nowhere -> treated as 'cannot judge' (STUN blocked?), no pointless switching OK")

# ۳) الان سرور خوبی نیست، دور بعد (retry) سرور تازه اضافه شده → همون‌جا پیداش می‌کنه
act, calls, checked = setup([poor, poor, good], lambda c: good if c["host"] == "22.0.0.1" else poor)
W.CALL_MAX_RETRIES = 3
W.POOL["standby"] = [mk("22.0.0.7")]
def late():
    time.sleep(0.3); W.POOL["standby"].append(mk("22.0.0.1"))
threading.Thread(target=late, daemon=True).start()
W.CALL_RETRY_SECS = 1
W.call_prepare(W.GEN[0], "balanced", True)
assert calls == ["22.0.0.1"], (calls, checked, W.S["note"])
print("3) nothing good now -> keeps best available, retries, finds the newly added server OK")

# ۴) خود سرور فعلی قابل‌قبوله (fair) و جایگزین بهتری نیست → ساکت می‌مونه و پیام «پیدا نشد» می‌ده (نه خطا)
fair = q(loss=1, p50=120, jitter=20)
act, calls, checked = setup([fair], lambda c: fair)
W.POOL["standby"] = [mk("23.0.0.1")]
W.call_prepare(W.GEN[0], "balanced", True)
assert not calls and W.POOL["active"][0] is act
print("4) acceptable current server stays when nothing is clearly better OK")

# ۵) یک جستجو در لحظه؛ دومی بلافاصله برمی‌گرده
assert W.CALL_SEARCH.acquire(blocking=False)
try:
    t0 = time.time(); W.call_prepare(W.GEN[0], "balanced", True); assert time.time() - t0 < 1
finally:
    W.CALL_SEARCH.release()
print("5) only one call-search at a time OK")

# ۶) ناظر مقاوم: خطای غیرمنتظره ناظر رو برای همیشه نمی‌کشه
W.STOP.clear(); W.GEN[0] += 1; g = W.GEN[0]; n = [0]
@W.resilient
def flaky(gen):
    n[0] += 1
    if n[0] < 2: raise RuntimeError("boom")
    while W.GEN[0] == gen: time.sleep(0.05)
real = W.time.sleep; W.time.sleep = lambda x: real(0.01)
th = threading.Thread(target=flaky, args=(g,), daemon=True); th.start(); real(0.3)
assert n[0] == 2 and th.is_alive(); W.GEN[0] += 1; real(0.2); W.time.sleep = real; assert not th.is_alive()
print("6) watcher restarts after an exception instead of dying forever OK")

# ۷) schema منابع: ردیف ناقص/خراب → پیش‌فرض می‌گیره، بقیه سالم
W.SRC_DB.write_text(json.dumps({"sources": [{"url": "https://a.example/x"}, {"url": "https://b.example/y", "on": "false", "got": "x", "alive": True},
                                             {"url": "https://c.example/z", "on": False, "got": 5, "alive": 2}, 7, {"nourl": 1}]}), encoding="utf-8")
db = W.load_db(); by = {s["url"]: s for s in db["sources"]}
assert by["https://a.example/x"]["on"] is True and by["https://b.example/y"]["on"] is True and by["https://b.example/y"]["got"] == 0
assert by["https://c.example/z"]["on"] is False and by["https://c.example/z"]["got"] == 5 and len(db["sources"]) >= 3
print("7) malformed sources rows get safe defaults, valid rows untouched OK")

# ۸) main(): قفل تک‌نمونه‌ای قبل از دست‌زدن به PID/پراکسی
import inspect
src = inspect.getsource(W.main)
assert src.index("LOCK_PORT") < src.index("xray.pid") < src.index("restore_proxy()")
print("8) single-instance lock is taken before touching the saved PID / system proxy OK")
print("ALL OK")
