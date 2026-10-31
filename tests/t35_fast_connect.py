# اتصال سریع‌تر: به‌محض اینکه یک سرور هر سه سایت رو باز کرد وصل می‌شه (نه بعد از کندترین سرور)، تست تکراری نداریم،
# و ردپای نشست‌های قبلی بعد از بستن برنامه می‌مونه.
import sys, os, time, tempfile, threading, json
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W, cfgtrace as T

ok = 0
def check(name, cond):
    global ok
    print(("OK   " if cond else "FAIL ") + name)
    if not cond:
        sys.exit(1)
    ok += 1

def mk(raw):
    return {"raw": raw, "proto": "vless", "network": "ws", "security": "tls", "port": 443, "host": raw, "flags": set(), "alive": True, "lat": 100}

fast, slow1, slow2 = mk("fast"), mk("slow1"), mk("slow2")
calls = []
def fake_check(c, rounds=1, timeout=3, speed=False, secs=3.0, sites=False, call=None, up=None):
    calls.append(c["raw"])
    cc = dict(c); cc["flags"] = set(c["flags"])
    if c["raw"] == "fast":
        time.sleep(0.2); cc["sites"] = {"yt": True, "ig": True, "tg": True}
    else:
        time.sleep(3.0); cc["sites"] = {"yt": False, "ig": False, "tg": False}
    cc["alive"] = True
    return cc
W.check = fake_check
W.learn_record = lambda *a, **k: None
W.bad_clear = lambda *a, **k: None
W.bad_mark = lambda *a, **k: None
W.learn_order = lambda c: 0.0

cache = {}
t0 = time.time()
res = W.sites_pick([fast, slow1, slow2], cache)
dt = time.time() - t0
check("برمی‌گرده به‌محض اولین سرور خوب (نه بعد از ۳ ثانیهٔ کندترین)", dt < 1.5 and [r["raw"] for r in res] == ["fast"])
check("تست‌های کند هنوز در جریان‌ان و علامت دارن", {"slow1", "slow2"} <= W.SITE_INFLIGHT)

# فراخوانی دوباره: سرور در جریان دوباره تست نمی‌شه
n_before = len(calls)
res2 = W.sites_pick([fast, slow1, slow2], cache)
check("سرور در جریان دوباره تست نمی‌شه", len(calls) == n_before and [r["raw"] for r in res2] == ["fast"])

time.sleep(3.3)
check("بعد از اتمام، نتیجه‌ی کندها هم توی cache اومد و علامت‌ها پاک شد", {"fast", "slow1", "slow2"} <= set(cache) and not W.SITE_INFLIGHT)
check("سرور بدون هر سه سایت انتخاب نمی‌شه", [r["raw"] for r in W.sites_pick([fast, slow1, slow2], cache)] == ["fast"])

# ردپای نشست قبلی
T.reset(); T.evt("switch", "تست"); T.incident("switch", why="x")
p = os.path.join(os.environ["CFG_DATA"], "trace_last.json")
T.save_tail(p, {"series": [{"t": 1}]})
d = T.load_prev(p)
check("ردپا ذخیره و خونده می‌شه", d and d["events"][-1][1] == "switch" and d["incidents"][-1]["kind"] == "switch" and d["extra"]["series"][0]["t"] == 1)
open(p, "w").write("{bad json")
check("فایل خراب نادیده گرفته می‌شه", T.load_prev(p) is None)

# چرخش: نشست طولانی با نشست کوتاهِ بعدی گم نمی‌شه
W.DATA = __import__("pathlib").Path(os.environ["CFG_DATA"])
T.reset(); T.evt("switch", "نشست اول"); T.save_tail(W.DATA / "trace_last.json")
s1 = W.rotate_prev_sessions()
check("چرخش اول: نشست اول خونده شد", len(s1) == 1 and s1[0]["events"][-1][2] == "نشست اول")
T.reset(); T.evt("switch", "نشست دوم"); T.save_tail(W.DATA / "trace_last.json")
s2 = W.rotate_prev_sessions()
check("چرخش دوم: هر دو نشست هست، جدیدترین اول", [x["events"][-1][2] for x in s2] == ["نشست دوم", "نشست اول"])
check("فایل‌ها چرخیدن", (W.DATA / "trace_prev1.json").is_file() and not (W.DATA / "trace_last.json").is_file())
print(f"\n{ok} بررسی رد شد")
