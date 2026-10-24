import sys, os, threading, http.client, json, tempfile, time
os.environ["CFG_DATA"] = tempfile.mkdtemp(); os.environ["CFG_NO_RESTART"] = "1"; sys.path.insert(0, '.')
import cfgweb as W
# سیاست حالت تماس: حالت تماس فرمانده‌ست؛ سرعت اسکن و حالت جابه‌جایی رو خودش مدیریت می‌کنه، روشن‌شدنش خودش اتصال رو شروع می‌کنه،
# و انتخاب کاربر دست‌نخورده می‌مونه و با خاموش‌شدن برمی‌گرده.
srv = W.http.server.ThreadingHTTPServer(("127.0.0.1", 0), W.H); W.PORT = srv.server_address[1]; W.TOKEN = "TT"
threading.Thread(target=srv.serve_forever, daemon=True).start()
def call(path, body=None):
    c = http.client.HTTPConnection("127.0.0.1", W.PORT)
    c.request("POST", path, body=json.dumps(body or {}), headers={"Host": f"127.0.0.1:{W.PORT}", "Content-Type": "application/json", "X-T": "TT"})
    r = c.getresponse(); return json.loads(r.read() or b"{}")
def waitfor(cond, secs=3):
    t = time.time() + secs
    while time.time() < t:
        if cond(): return True
        time.sleep(0.05)
    return False

# ---- ۱) سرعت و حالت مؤثر
W.CALL[0] = False; W.SPEED[0] = "turbo"; W.S["stage"] = "idle"
assert W.eff_speed() == "turbo" and W.speed_params()["rate"] == 60 and W.eff_mode("fast") == "fast"
W.CALL[0] = True
assert W.eff_speed() == "normal" and W.speed_params()["rate"] == 15, "موقع وصل‌شدن از متعادل تندتر نمی‌ره"
W.S["stage"] = "connected"
assert W.eff_speed() == "gentle" and W.speed_params()["rate"] == 6, "وسط اتصال پردازش پس‌زمینه حداقل"
W.SPEED[0] = "gentle"; W.S["stage"] = "idle"; assert W.eff_speed() == "gentle"
assert W.eff_mode("fast") == "stable" and W.eff_mode("stable") == "stable" and W.eff_mode("off") == "off", "«ثابت» انتخاب صریح کاربره"
assert W.SPEED[0] == "gentle"
W.SPEED[0] = "turbo"; W.CALL[0] = False; assert W.eff_speed() == "turbo", "با خاموش‌شدن حالت تماس انتخاب کاربر برمی‌گرده"
print("1) effective speed/mode OK")

# ---- ۲) فاز و وضعیت
W.CALL[0] = False; assert W.call_phase() == "" and W.call_state()["managed"] is None
W.CALL[0] = True
W.S["stage"] = "idle"; assert W.call_phase() == "idle"
W.S["stage"] = "running"; assert W.call_phase() == "connecting"
W.S["stage"] = "connected"; W.S["call"] = None; assert W.call_phase() == "monitoring"
W.CALL_SEARCH.acquire(); assert W.call_phase() == "searching"; W.CALL_SEARCH.release()
W.S["call"] = {"udp_ok": False}; assert W.call_phase() == "no_udp"
W.S["call"] = W.cfgcall.assess([40.0 + (i % 3) for i in range(40)]); assert W.cfgcall.call_ok(W.S["call"], "good") and W.call_phase() == "locked", W.S["call"]
m = W.call_state()["managed"]; assert m["speed"] == "gentle" and m["mode"] == "stable" and m["speed_user"] == W.SPEED[0]
print("2) phases + managed state OK")

# ---- ۳) روشن‌شدن حالت تماس خودش اتصال رو شروع می‌کنه (با تنظیمات ذخیره‌شده)
W.CALL[0] = False; W.S["call"] = None
started, prepped = [], []
real_start, real_prep = W.start_session, W.call_prepare
W.start_session = lambda j: started.append(dict(j)) or {"ok": True}
W.call_prepare = lambda *a, **k: prepped.append(a)
W.save_settings({"profile": "stable", "mode": "fast", "speed": "fast", "direct": "ir", "sysproxy": True, "quick": True})
W.S["stage"] = "idle"
r = call("/api/call", {"on": True}); assert r["ok"] and r["call"]["on"] and r["call"]["managed"]["mode"] == "stable"
assert waitfor(lambda: started), "وصل نبود: باید اتصال شروع بشه"
j = started[0]; assert j["profile"] == "stable" and j["direct"] == "ir" and j["speed"] == "fast" and j["mode"] == "fast", j  # انتخاب‌های کاربر دست‌نخورده
call("/api/call", {"on": False}); started.clear(); W.S["stage"] = "running"
call("/api/call", {"on": True}); time.sleep(0.4); assert not started and not prepped, "وسط جستجو دوباره شروع نمی‌شه"
call("/api/call", {"on": False}); W.S["stage"] = "connected"
call("/api/call", {"on": True}); assert waitfor(lambda: prepped) and not started, "وصل بودی: فقط دنبال سرور تماس می‌گرده"
r = call("/api/call", {"on": False}); assert r["call"]["on"] is False and W.CALL[0] is False
assert json.loads(open(W.SETTINGS).read())["speed"] == "fast", "خاموش‌شدن چیزی از تنظیمات کاربر پاک نکرده"
print("3) turning call mode on starts the connection; off restores the user's choices OK")

# ---- ۴) دکمه‌ی اتصال هنوز همون مسیر قبلیه (start_session واقعی با pipeline ساختگی)
W.start_session, W.call_prepare = real_start, real_prep
runs = []
real_pipe = W.pipeline
W.pipeline = lambda *a, **k: runs.append(a)
W.S["stage"] = "idle"
r = call("/api/start", {"profile": "speed", "quick": False, "sysproxy": False, "mode": "off", "direct": "ir", "tgonly": True, "speed": "gentle"})
assert waitfor(lambda: runs), "pipeline شروع نشد"
assert runs[0] == ("speed", False, False, "off"), runs[0]
assert W.DIRECT[0] == "ir" and W.TGONLY[0] is True and W.VPN_WANT[0] is False and W.SPEED[0] == "gentle"
W.pipeline = real_pipe
print("4) /api/start through start_session OK")

# ---- ۵) پیام تنظیم وقتی حالت تماس فرمانده‌ست
W.CALL[0] = True
msg = " ".join(W.apply_live({"speed": "fast"}, {"speed": "normal"}))
assert "حالت تماس" in msg and "مدیریت" in msg, msg
W.CALL[0] = False
msg = " ".join(W.apply_live({"speed": "turbo"}, {"speed": "normal"}))
assert "مدیریت" not in msg and "اعمال شد" in msg, msg
print("ALL OK")
