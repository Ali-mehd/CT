# مهلت پراب سلامت با کندیِ واقعیِ سرور تنظیم می‌شه؛ سرور سریعِ ناگهان‌مرده همون مهلتِ کوتاه رو می‌گیره
import sys, os, tempfile
os.environ["CFG_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, '.')
import cfgweb as W
f = W.probe_timeout_for
assert f([]) == 3.0 and f([900, 800, None]) == 3.0, "نمونه‌ی کم = پیش‌فرض"
assert f([900, 1000, 800, 950, 1100, None, None, None]) == 3.0, "سرور سریع که تازه کند جواب داد/مرد: مهلت کوتاه می‌مونه"
assert 4.0 < f([2000, 2200, 1900, 2100, None]) < 5.5
assert f([3866, 4794, 3900, 4100, 4500]) == 7.0, "سقف ۷ ثانیه"
assert f([5900] * 6) == 7.0
print("t36 OK")
