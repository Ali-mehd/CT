import re, sys
from html.parser import HTMLParser
from pathlib import Path
# ساختار صفحه: تگ‌ها بسته باشن، هر شناسه‌ای که اسکریپت صدا می‌زنه توی صفحه باشه، سه تب، تنظیمات خودکار پنهان، بخش سازنده پیش‌فرض پنهان.
src = (Path(__file__).resolve().parent.parent / "app" / "src" / "main" / "assets" / "web" / "ui.html").read_text(encoding="utf-8")
page, script = src.split("<script>", 1)
class P(HTMLParser):
    def __init__(s): super().__init__(); s.st, s.err, s.ids = [], [], set()
    def handle_starttag(s, t, a):
        d = dict(a)
        if "id" in d: s.ids.add(d["id"])
        if t not in ("input", "br", "hr", "meta", "link", "img"): s.st.append((t, s.getpos()[0]))
    def handle_endtag(s, t):
        if t in ("input", "br", "hr"): return
        if not s.st or s.st[-1][0] != t: s.err.append((t, s.getpos()[0]))
        else: s.st.pop()
p = P(); p.feed(page)
assert not p.err, p.err[:3]
assert [t for t, _ in p.st] == ["html", "body"], p.st  # فقط html و body باز می‌مونن (مثل قبل)
used = set(re.findall(r'\$\("([A-Za-z0-9_\-]+)"\)', script)) - {"toast"}  # toast داخل اسکریپت ساخته می‌شه
missing = sorted(used - p.ids); assert not missing, missing
assert re.search(r'const TB=\[\["srv","[^"]+"\],\["adv","[^"]+"\],\["help","[^"]+"\]\];', script), "باید فقط سه تب باشه"
for pane in ("srv", "adv", "help"): assert f'data-p="{pane}"' in page, pane
assert 'data-p="an"' not in page and 'data-p="more"' not in page, "پنل‌های قدیمی باید داخل «پیشرفته» رفته باشن"
for i in ("setd", "sec-add", "sec-an", "sec-diag", "sec-more"): assert f'id="{i}"' in page, i
assert re.search(r'id="sec-evo"[^>]*\bhidden\b', page), "بخش سازنده باید پیش‌فرض پنهان باشه"
# تنظیم‌هایی که خودکار شدن: پنهان از کاربر، ولی عنصرشون برای اسکریپت باقی مونده
for i in ("autosrc", "sysrow", "h-as", "h-sys", "h-q"): assert re.search(rf'class="[^"]*\bauto\b[^"]*"[^>]*id="{i}"|id="{i}"[^>]*class="[^"]*\bauto\b', page) or i == "autosrc", i
assert page.count('class="row auto"') >= 3 and ".auto{display:none!important}" in page
assert 'ui2' in script, "مهاجرت یک‌باره‌ی تنظیمات خودکار"
print("UI structure OK: tabs=3, sections nested, ids all present, auto settings hidden")
