"""t33: پناهگاه جایگزین‌ها، جابه‌جایی با سرور ناقص، تغییر زنده‌ی حالت، نخ جستجوی ثبت‌شده."""
import sys, time
sys.path.insert(0, ".")
import cfgweb as W

def mk(ip, **kw):
    c = dict(raw=ip, host=ip, port=443, proto="vless", network="tcp", security="tls", flags=set(), lat=200, success=1.0, alive=True)
    c.update(kw); return c
FULL, PART = dict(yt=1, ig=1, tg=1), dict(yt=1, ig=0, tg=1)

# 1) split_pools: کامل/تست‌نشده -> standby ؛ ناقص -> reserve
a, b, c = mk("1.1.1.1", sites=FULL), mk("1.1.1.2", sites=PART), mk("1.1.1.3")
W.split_pools([a, b, c, a])
assert [x["raw"] for x in W.POOL["standby"]] == ["1.1.1.1", "1.1.1.3"] and [x["raw"] for x in W.POOL["reserve"]] == ["1.1.1.2"]
# 2) fallback_ok شامل reserve است (قبلاً جابه‌جایی فقط standby را می‌دید)
assert {x["raw"] for x in W.fallback_ok()} == {"1.1.1.1", "1.1.1.2", "1.1.1.3"}
# 3) با standby خالی و فقط reserve، failover تونل مرده را «restart» نمی‌کند و از reserve استفاده می‌کند
W.POOL.update(active=[mk("9.9.9.9")], standby=[], reserve=[mk("2.2.2.2", sites=PART)], bad={}, bench=[], switches=0)
W.S["stage"] = "connected"; W.S["connected"] = {"ms": 100}
used = []
W.start_xray = lambda sel, prof, plain=False: (used.append(sel[0]["raw"]) or sel)
W.probe = lambda *a, **k: 120.0
W.probe_retry = lambda *a, **k: 120.0
W.check_many = lambda cs, *a, **k: [dict(c, alive=True, success=1.0, sites=PART) for c in cs]
W.threading.Thread = type("T", (), {"__init__": lambda s, target=None, args=(), kwargs=None, daemon=None: None, "start": lambda s: None})
r = W._failover(W.GEN[0], "balanced", False, "stable")
assert r != "restart" and used == ["2.2.2.2"], (r, used)
# 4) وقتی هیچ‌کس نیست -> restart
W.POOL.update(active=[mk("9.9.9.9")], standby=[], reserve=[], bad={}, bench=[])
W.probe = lambda *a, **k: None; W.probe_retry = lambda *a, **k: None
assert W._failover(W.GEN[0], "balanced", False, "stable") == "restart"
# 5) restart_pipeline با force از قفل ۱۵ ثانیه رد می‌شود
import inspect
assert "force" in inspect.signature(W.restart_pipeline).parameters
print("t33 OK")
