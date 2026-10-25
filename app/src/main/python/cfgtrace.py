"""cfgtrace - ردپای بی‌خطر برای «گزارش تکامل».

چرا؟ برنامه خیلی جاها خطا رو می‌بلعه (تا کرش نکنه) و فقط یک شمارنده‌ی کلی نگه می‌داشت؛ برای همین از روی گزارش نمی‌شد فهمید
«چرا جستجو کند بود»، «یوتیوب کی و چرا قطع شد» یا «وقت تست‌ها کجا رفت». اینجا چهار چیز نگه داشته می‌شه:
  evt   خط زمانی رویدادها (وصل شد، سرور عوض شد، سایت‌ها بسته شد، شبکه عوض شد، ...)
  err   خطاهای بلعیده‌شده: چند بار، کِی، چه نوعی
  perf  زمان‌سنجی (مثلاً هر تست زنده چند ثانیه طول کشید): تعداد، میانگین، میانه، p90، بیشینه
  run   زمان‌بندی هر جستجو: چند ثانیه تا شبکه‌سنجی، تا اولین کانفیگ رسیده، تا اولین سالم، تا اتصال، و چرا تموم شد
هیچ آدرس، IP، شناسه یا رمزی اینجا ذخیره نمی‌شه (فقط دسته‌ها، نوع خطا و عدد)؛ متن‌های آزاد کوتاه می‌شن و گزارش بعدش دوباره فیلتر می‌شه.
فقط کتابخانه‌ی استاندارد؛ هیچ‌جا وابسته به بقیه‌ی برنامه نیست (تا هم cfgscan و هم cfgweb بتونن واردش کنن)."""
import random
import threading
import time
from collections import deque

_L = threading.Lock()
T0 = time.time()
EVT = deque(maxlen=300)   # [ثانیه از شروع برنامه, نوع, توضیح کوتاه]
ERR = {}                  # "جا:نوع‌خطا" -> [تعداد, آخرین زمان, پیام کوتاه]
PERF = {}                 # کلید -> [n, sum, max, نمونه‌ها]
COUNT = {}                # شمارنده‌های ساده
RUNS = deque(maxlen=6)    # آخرین جستجوها
INC = deque(maxlen=8)     # «لحظه‌ی مشکل»: عکسِ کوچیکی از وضعیت وقتی چیزی خراب شد
_RUN = [None]
SAMPLES = 300


def evt(kind, detail=""):
    with _L:
        EVT.append([round(time.time() - T0, 1), str(kind)[:30], str(detail)[:140]])


def err(where, e):
    """یک خطای بلعیده‌شده رو ثبت می‌کنه (تعداد + آخرین زمان + پیام کوتاه)."""
    k = f"{where}:{type(e).__name__}"[:60]
    with _L:
        v = ERR.get(k)
        if v is None:
            if len(ERR) >= 60:
                return
            v = ERR[k] = [0, 0.0, ""]
        v[0] += 1
        v[1] = round(time.time() - T0, 1)
        v[2] = str(e)[:100]


def count(key, n=1):
    with _L:
        COUNT[key] = COUNT.get(key, 0) + n


def perf(key, v):
    """یک زمان‌سنجی (ثانیه). فقط تا SAMPLES نمونه‌ی تصادفی (reservoir) نگه می‌داره؛ حافظه ثابت می‌مونه."""
    with _L:
        p = PERF.get(key)
        if p is None:
            if len(PERF) >= 40:
                return
            p = PERF[key] = [0, 0.0, 0.0, []]
        p[0] += 1
        p[1] += v
        p[2] = max(p[2], v)
        if len(p[3]) < SAMPLES:
            p[3].append(v)
        else:
            i = random.randrange(p[0])
            if i < SAMPLES:
                p[3][i] = v


def run_begin(**info):
    with _L:
        r = {"t0": time.time(), "at": round(time.time() - T0, 1), "info": {k: v for k, v in info.items()}, "marks": {}, "end": None}
        RUNS.append(r)
        _RUN[0] = r


def run_mark(name, **extra):
    """یک نقطه‌ی زمانی توی جستجوی جاری؛ فقط بار اول هر نام ثبت می‌شه (مثلاً «اولین سالم»)."""
    with _L:
        r = _RUN[0]
        if r is None or name in r["marks"]:
            return
        r["marks"][name] = round(time.time() - r["t0"], 1)
        if extra:
            r["info"].update(extra)


def run_end(why="", **extra):
    with _L:
        r = _RUN[0]
        if r is None or r["end"] is not None:
            return
        r["end"] = {"s": round(time.time() - r["t0"], 1), "why": str(why)[:160]}
        r["info"].update(extra)


def incident(kind, **state):
    """وقتی چیزی خراب شد، عکسی از وضعیتِ همان لحظه نگه می‌داره (بعداً کاربر لازم نیست یادش بیاد چی شد)."""
    with _L:
        INC.append({"t": round(time.time() - T0, 1), "kind": str(kind)[:40], "state": {k: v for k, v in state.items()}})


def _pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(len(xs) * q))]


def snapshot(max_events=120):
    """همه‌ی ردپا به‌صورت دیکشنری ساده (برای گزارش). زمان‌ها «ثانیه از شروع برنامه»اند؛ now همین لحظه است."""
    now = round(time.time() - T0, 1)
    with _L:
        perf = {k: {"n": p[0], "avg": round(p[1] / p[0], 3) if p[0] else None, "p50": _r(_pct(p[3], 0.5)), "p90": _r(_pct(p[3], 0.9)),
                    "max": round(p[2], 3)} for k, p in PERF.items()}
        runs = [{"at": r["at"], "info": dict(r["info"]), "marks": dict(r["marks"]), "end": r["end"]} for r in RUNS]
        return {"now": now, "events": list(EVT)[-max_events:], "errors": {k: list(v) for k, v in ERR.items()}, "perf": perf,
                "count": dict(COUNT), "runs": runs, "incidents": list(INC)}


def _r(x):
    return None if x is None else round(x, 3)


def reset():
    """فقط برای تست."""
    with _L:
        EVT.clear(); ERR.clear(); PERF.clear(); COUNT.clear(); RUNS.clear(); INC.clear(); _RUN[0] = None


def hints(snap, extra=None):
    """خلاصه‌ی خودکار «چی غیرعادیه» از روی ردپا؛ برای اینکه گزارش‌خوان (Claude یا آدم) اول از مهم‌ترین نکته‌ها شروع کنه.
    هر مورد: [سطح, متن]. سطح: high | mid | info. فقط از اعدادِ همین گزارش حساب می‌شه (حدس نیست؛ ولی «علت» پیشنهادی‌ش حدسه و همین‌طور نوشته می‌شه)."""
    extra = extra or {}
    out = []
    perf, cnt, runs = snap.get("perf") or {}, snap.get("count") or {}, snap.get("runs") or []
    live_ok, live_dead = perf.get("live_ok_s") or {}, perf.get("live_dead_s") or {}
    slot, pace = perf.get("slot_wait_s") or {}, perf.get("pace_wait_s") or {}
    n_live = (live_ok.get("n") or 0) + (live_dead.get("n") or 0)
    if n_live >= 30:
        avg_live = ((live_ok.get("avg") or 0) * (live_ok.get("n") or 0) + (live_dead.get("avg") or 0) * (live_dead.get("n") or 0)) / n_live
        if (slot.get("avg") or 0) > 0.5 * avg_live and avg_live > 0:
            out.append(["high", f"گلوگاه سرعت: هر تست زنده میانگین {avg_live:.1f}s طول می‌کشه و {slot['avg']:.1f}s هم منتظر جای خالیِ «تست هم‌زمان» می‌مونه؛ "
                                f"یعنی تعداد تست هم‌زمان (نه نرخ شروع) سقف سرعته."])
        if (pace.get("avg") or 0) > 0.5 * max(avg_live, 0.01):
            out.append(["mid", f"سقف نرخ شروع اتصال هم تأثیر داره (میانگین انتظار {pace['avg']:.2f}s برای هر تست)."])
        if (live_dead.get("p50") or 0) > 4:
            out.append(["mid", f"سرورهای مرده هم میانه {live_dead['p50']:.1f}s وقت می‌گیرن (مهلت‌ها بلنده)؛ مهلت یا تعداد تست هم‌زمان رو باید با واقعیت تنظیم کرد."])
    tot = cnt.get("test_total") or 0
    if tot >= 30:
        why = {k[4:]: v for k, v in cnt.items() if k.startswith("why:")}
        top = sorted(why.items(), key=lambda kv: -kv[1])[:4]
        out.append(["info", "علتِ زنده‌نبودن (از " + str(tot) + " تست): " + "، ".join(f"{k} {v * 100 // tot}٪" for k, v in top)])
        for k, v in why.items():
            if k in ("core_port", "core_exit") and v / tot > 0.08:
                out.append(["high", f"{v * 100 // tot}٪ تست‌ها فقط چون هسته‌ی تست (xray/sing-box) بالا نیومد خراب شدن ({k}) — حدس: فشار CPU/حافظه یا مهلت راه‌اندازی کوتاه، نه خرابیِ سرور."])
            if k == "timeout" and v / tot > 0.3:
                out.append(["mid", f"{v * 100 // tot}٪ تست‌ها بعد از وصل‌شدن تونل timeout شدن؛ مهلت کوتاه/شبکه‌ی کند یا فیلتر عمیق (حدس)."])
    for r in runs[-1:]:
        m, e = r.get("marks") or {}, r.get("end") or {}
        if m.get("first_alive") is None and (e.get("s") or 0) > 60:
            out.append(["high", f"آخرین جستجو {e['s']:.0f}s طول کشید و هیچ سروری زنده پیدا نکرد ({e.get('why', '')[:80]})."])
        elif (m.get("first_alive") or 0) > 90:
            out.append(["mid", f"اولین سرور زنده بعد از {m['first_alive']:.0f}s پیدا شد (دیر)."])
        if (m.get("fetch_done") or 0) > 40:
            out.append(["mid", f"دانلود منابع {m['fetch_done']:.0f}s طول کشید."])
    lb = cnt.get("conn:10013", 0) + cnt.get("conn:13", 0)
    if lb:
        out.append(["high", f"سیستم‌عامل/آنتی‌ویروس/فایروالِ همین دستگاه {lb} اتصال خروجی رو با کد «دسترسی ممنوع» بست (خرابیِ سرور حساب نشد)."])
    conn_codes = {k[5:]: v for k, v in cnt.items() if k.startswith("conn:") and k[5:] not in ("10013", "13")}
    if conn_codes:
        out.append(["info", "کدهای خطای اتصال TCP: " + "، ".join(f"{k}×{v}" for k, v in sorted(conn_codes.items(), key=lambda kv: -kv[1])[:5])])
    okn = (perf.get("tcp_ok_s") or {}).get("n") or 0
    if okn >= 50 and cnt.get("tcp_instant", 0) / okn > 0.05:
        out.append(["mid", f"{cnt['tcp_instant'] * 100 // okn}٪ اتصال‌های موفق TCP کمتر از ۱ms طول کشیدن؛ برای آدرس‌های دور غیرعادیه و می‌تونه نشانه‌ی رهگیری توسط نرم‌افزار امنیتی محلی باشه (حدس، تأییدنشده)."])
    if cnt.get("refused_fast", 0) >= 20:
        out.append(["mid", f"{cnt['refused_fast']} اتصال در کمتر از ۳ms «رد» شد؛ رد شدن واقعی از راه دور حداقل یک RTT طول می‌کشه، پس احتمالاً محلیه (حدس)."])
    lg = extra.get("loadguard") or {}
    if lg.get("on") and (lg.get("min_f") or 1) < 0.7:
        out.append(["high", f"ترمز CPU فعال شد (کمترین ضریب {lg['min_f']}؛ دیرکرد پردازه {lg.get('lag_s')}s، سهم CPU {lg.get('duty')}) — گوشی/پردازه تحت فشار بوده."])
    errs = snap.get("errors") or {}
    if errs:
        top = sorted(errs.items(), key=lambda kv: -kv[1][0])[:3]
        out.append(["mid", "خطاهای بلعیده‌شده: " + "؛ ".join(f"{k}×{v[0]}" for k, v in top)])
    ev = snap.get("events") or []
    sw = [e for e in ev if e[1] == "switch"]
    if len(sw) >= 3:
        out.append(["mid", f"{len(sw)} جابه‌جایی سرور در رویدادهای اخیر؛ آخرین دلیل: {sw[-1][2][:80]}"])
    nc = [e for e in ev if e[1] == "net_change"]
    if nc:
        out.append(["info", f"{len(nc)} بار نوع شبکه عوض شده (مودم/نت همراه/هات‌اسپات)."])
    inc = snap.get("incidents") or []
    if inc:
        out.append(["mid", f"{len(inc)} «لحظه‌ی مشکل» ثبت شده؛ آخرین: {inc[-1]['kind']} (بخش incidents)."])
    for k, v in (extra.get("flags") or {}).items():
        out.append(["mid", v])
    order = {"high": 0, "mid": 1, "info": 2}
    out.sort(key=lambda h: order.get(h[0], 3))
    return out
