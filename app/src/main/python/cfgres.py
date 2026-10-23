"""cfgres - تنظیم خودکارِ مصرف منابع در اندروید («ریشه‌ی گیاه»).
جاوا هر چند ثانیه وضعیت واقعی گوشی (رم، دما، باتری، صرفه‌جویی، صفحه) رو می‌ده؛ این ماژول یک «ضریب» بین ۰٫۱ و ۱ می‌سازه:
  • خطر (داغ شدن، کمبود رم، باتری ضعیف) ⇒ ضریب فوراً پایین میاد (ریشه‌ها زود جمع می‌شن)
  • اوضاع خوب ⇒ ضریب آروم و پله‌ای بالا می‌ره (ریشه‌ها کم‌کم رشد می‌کنن) و بعد از هر کاهش مدتی صبر می‌کنه (نوسان نسازه)
سیگنالِ نامعلوم هیچ‌وقت محدودیت نمی‌سازه؛ فقط «سقفِ ظرفیت دستگاه» (از رم/هسته‌ها) همیشه اعمال می‌شه.
خروجی: تعداد تست زنده‌ی هم‌زمان (هر کدوم یک پردازه‌ی xray)، نرخ اتصال آزمایشی در ثانیه، و تعداد نخ‌ها.
فقط برای اندروید استفاده می‌شه؛ تا وقتی جاوا داده نداده، هیچ تغییری نمی‌ده (نسخه‌ی PC دست‌نخورده می‌مونه)."""
import threading
import time
from collections import deque

BOOT_LIVE = 2            # تا وقتی رم واقعی یک پردازه اندازه‌گیری نشده، بیشتر از این تست هم‌زمان نمی‌کنیم (از کم شروع، با شواهد رشد)
MARGIN = 1.3             # حاشیه‌ی ایمنی روی رم اندازه‌گیری‌شده‌ی هر پردازه (نخ‌ها و بافرها؛ «حاشیه»ست نه تخمینِ ظرفیت)
NO_THERMAL_CAP = 0.5     # وقتی هیچ سنسور دمایی در دسترس نیست، با نصف توان کار می‌کنیم و به کاربر می‌گیم
FLOOR = 0.12             # کمترین ضریب (هیچ‌وقت صفر نمی‌شه؛ اتصال فعلی و نظارت همچنان کار می‌کنن)
GROW_STEP = 0.06         # رشد در هر بروزرسانی (~۵ ثانیه) ⇒ از کف تا سقف حدود ۱ دقیقه
HOLD_AFTER_SHRINK = 45   # بعد از هر کاهش، تا این‌قدر ثانیه رشد نمی‌کنه
STALE = 40               # داده‌ی جاوا اگه از این‌قدر ثانیه قدیمی‌تر باشه نادیده گرفته می‌شه (سرویس مرده/گیر کرده)


def _num(v, lo=-1e9, hi=1e9):
    try:
        x = float(v)
    except (TypeError, ValueError, OverflowError):
        return None
    return x if lo <= x <= hi and x == x else None


class Governor:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.lock = threading.Lock()
        self.env = {}
        self.t_env = 0.0
        self.s = 1.0              # ضریب فعلی
        self.hold_until = 0.0
        self.temps = deque(maxlen=40)  # (زمان، دما) برای روند
        self.why = ""             # آخرین دلیل کاهش (فارسی، برای نمایش)
        self.proc_mb = None       # رم واقعی هر پردازه‌ی xray (اندازه‌گیری‌شده)؛ تا اندازه‌گیری نشده None
        self.mem_live = BOOT_LIVE  # سقف تست هم‌زمان از روی رم «واقعی»
        self.trim_t, self.trim_lv = 0.0, 0
        self.log = []             # (زمان، ضریب، دلیل) برای تست/گزارش
        self.notemp = "gentle"    # اگه هیچ سنسور دمایی نباشه: gentle = نصف توان (با اعلام به کاربر) | full = بدون این محدودیت (انتخاب کاربر)

    # ------------------------------------------------------------ ورودی
    def feed(self, env):
        """env: دیکشنری از جاوا. کلیدها (همه اختیاری): ram_total_mb, ram_avail_mb, low_mem, low_ram, cores, thermal (۰..۶ یا -۱),
        headroom (۰..۱+ یا -۱), batt_pct, batt_temp_c, charging, power_save, screen_on, trim (سطح onTrimMemory)."""
        if not isinstance(env, dict):
            return
        now = self.clock()
        with self.lock:
            self.env = env
            self.t_env = now
            t = _num(env.get("batt_temp_c"), -20, 90)
            if t is not None:
                self.temps.append((now, t))
            tl = _num(env.get("trim"), 0, 100)
            if tl and tl >= 5:
                self.trim_t, self.trim_lv = now, int(tl)
            self._mem(env)
            self._update(now)

    def note_proc_mb(self, mb):
        """رم واقعی (MB) یک پردازه‌ی xray/sing-box که پایتون از /proc خونده. اولین اندازه‌گیری جایگزین «هیچی» می‌شه؛ بعدی‌ها میانگین نرم."""
        m = _num(mb, 1, 2000)
        if m:
            with self.lock:
                self.proc_mb = m if self.proc_mb is None else 0.7 * self.proc_mb + 0.3 * m
                self._mem(self.env)

    def _mem(self, e):
        total, avail = _num(e.get("ram_total_mb"), 0, 1e6), _num(e.get("ram_avail_mb"), 0, 1e6)
        if self.proc_mb is None or not total or avail is None:
            self.mem_live = BOOT_LIVE  # رم یا مصرف پردازه اندازه‌گیری نشده ⇒ از کم شروع (حدس نمی‌زنیم)
            return
        reserve = max(400.0, 0.15 * total)  # رمی که برای خود اندروید و برنامه‌های دیگه کنار می‌ذاریم
        self.mem_live = max(1, int((avail - reserve) / (self.proc_mb * MARGIN)))

    # ------------------------------------------------------------ سقف‌ها (هر کدوم عددی بین ۰ و ۱)
    def _caps(self, e, now, m=False):
        """m=True: نسخه‌ی «بدبینانه» برای تصمیمِ رشد (هیسترزیس): برای بالا رفتن، سیگنال باید کمی پایین‌تر از آستانه باشه."""
        c = {}
        if e.get("low_mem"):
            c["رم گوشی خیلی کم است"] = 0.15
        if now - self.trim_t < 120:
            lv = self.trim_lv
            c["سیستم رم می‌خواهد"] = 0.15 if lv >= 15 else 0.4 if lv >= 10 else 0.7
        th = _num(e.get("thermal"), -1, 10)
        if th is not None and th >= 0:
            c["گوشی داغ است"] = 1.0 if th <= 1 else 0.5 if th <= 2 else 0.25 if th <= 3 else FLOOR
        hr = _num(e.get("headroom"), 0, 10)
        if hr is not None and m:
            hr += 0.05
        if hr is not None:  # ۱٫۰ = رسیدن به حد محدودسازی سیستم
            c["به آستانه‌ی دمای سیستم نزدیکیم"] = 1.0 if hr < 0.7 else 0.85 if hr < 0.85 else 0.6 if hr < 0.95 else 0.3
        bt = _num(e.get("batt_temp_c"), -20, 90)
        if bt is not None and m:
            bt += 1.0
        if bt is not None:
            c["دمای باتری بالاست"] = (1.0 if bt < 37 else 0.85 if bt < 39 else 0.6 if bt < 42 else 0.3 if bt < 45 else FLOOR)
            ts = [(t, v) for t, v in self.temps if now - t <= 90]
            if len(ts) >= 3 and bt >= 36 and bt - ts[0][1] >= (1.0 + (1.0 if m else 0)):
                c["دمای باتری سریع بالا می‌ره"] = 0.5  # قبل از رسیدن به آستانه عقب می‌کشیم
        pct, chg = _num(e.get("batt_pct"), 0, 100), bool(e.get("charging"))
        if pct is not None and m:
            pct -= 3
        if pct is not None and not chg:
            c["باتری کم است"] = 0.15 if pct < 10 else 0.4 if pct < 20 else 0.7 if pct < 35 else 1.0
        if e.get("power_save"):
            c["حالت صرفه‌جویی باتری روشنه"] = 0.4
        if e.get("screen_on") is False and not chg:
            c["صفحه خاموش است"] = 0.6
        if th is None and hr is None and bt is None and self.notemp != "full":  # کاربر می‌تونه «بدون محدودیت» رو انتخاب کنه
            c["هیچ سنسور دمایی در دسترس نیست (برای احتیاط نصف توان)"] = NO_THERMAL_CAP
        return c

    @staticmethod
    def _min(caps):
        tgt, why = 1.0, ""
        for k, v in caps.items():
            if v < tgt:
                tgt, why = v, k
        return max(FLOOR, tgt), why

    def _update(self, now):
        down, why = self._min(self._caps(self.env, now))
        up, why_up = self._min(self._caps(self.env, now, True))
        if down < self.s - 1e-9:   # خطر: فوراً عقب‌نشینی
            self.s, self.why = down, why
            self.hold_until = now + HOLD_AFTER_SHRINK
            self.log.append((now, round(self.s, 3), why))
        elif up > self.s + 1e-9 and now >= self.hold_until:  # اوضاع با حاشیه‌ی اطمینان خوبه: آروم رشد کن
            self.s = min(up, self.s + GROW_STEP)
            self.why = "" if self.s >= 0.999 else (why_up or self.why)
        elif self.s < 0.999:
            self.why = why or why_up or self.why

    # ------------------------------------------------------------ خروجی
    def active(self):
        return bool(self.t_env) and self.clock() - self.t_env <= STALE

    def scale(self):
        return self.s if self.active() else 1.0

    def apply(self, p):
        """p = dict(rate, live, workers) از SPEEDS؛ نسخه‌ی تنظیم‌شده برمی‌گرده. بدون داده‌ی جاوا (مثلاً PC) همون p."""
        q = dict(p)
        if self.active():
            s = self.s
            q["live"] = max(1, min(int(round(q["live"] * s)), self.mem_live))
            q["rate"] = max(1.5, q["rate"] * s)
            q["workers"] = max(4, int(round(q["workers"] * max(s, 0.3))))
        return q

    def workers(self, n):
        """برای check_many: تعداد نخ‌ها با ضریب کم می‌شه (حداقل ۱)."""
        return max(1, int(round(n * self.scale()))) if self.active() else n

    def sensors(self):
        """کدوم سیگنال‌ها واقعاً اندازه‌گیری می‌شن؟ (برای شفافیت با کاربر)"""
        e = self.env if self.active() else {}
        has = lambda k: _num(e.get(k)) is not None
        return {"رم": has("ram_avail_mb") and has("ram_total_mb"), "رم هر پردازه": self.proc_mb is not None,
                "دمای باتری": has("batt_temp_c"), "وضعیت دمای سیستم": has("thermal"), "حاشیه‌ی دمایی سیستم": has("headroom"),
                "باتری": has("batt_pct")}

    def report_fa(self):
        """متن شفاف: چه چیزهایی اندازه‌گیری می‌شن و چه چیزهایی نه (و برنامه در نبودشون چی‌کار می‌کنه)."""
        sn = self.sensors()
        miss = [k for k, v in sn.items() if not v]
        if not self.active():
            return "هنوز داده‌ای از گوشی نرسیده."
        t = "اندازه‌گیری می‌شه: " + "، ".join(k for k, v in sn.items() if v) + "."
        if miss:
            t += " در دسترس نیست: " + "، ".join(miss) + "."
            if not (sn["دمای باتری"] or sn["وضعیت دمای سیستم"] or sn["حاشیه‌ی دمایی سیستم"]):
                t += " چون دما معلوم نیست با نصف توان کار می‌کنم."
            if not sn["رم هر پردازه"]:
                t += " تا رم واقعی یک پردازه اندازه‌گیری نشده حداکثر ۲ تست هم‌زمان."
        return t

    def temp_blind(self):
        sn = self.sensors()
        return self.active() and not (sn["دمای باتری"] or sn["وضعیت دمای سیستم"] or sn["حاشیه‌ی دمایی سیستم"])

    def summary(self):
        if not self.active():
            return ""
        if self.s >= 0.97:
            return ""
        return f"سرعت اسکن موقتاً {int(self.s * 100)}٪ شد ({self.why or 'در حال برگشت به حالت عادی'})"


GOV = Governor()
