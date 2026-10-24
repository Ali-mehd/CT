"""report - آمار اینکه چه نوع کانفیگ و با چه روشی روی شبکه‌ی خود کاربر کار می‌کنه، و ساخت فایل گزارش.
فقط شمارنده‌های کلی ذخیره می‌شه؛ هیچ آدرس سرور، شناسه یا رمزی توی گزارش نیست و می‌شه بی‌خطر نگهش داشت."""
import html
import json
import time
from pathlib import Path

UNSAFE = {"tls_verify_fail", "tamper", "insecure_cert", "blocklisted", "private_addr"}
FAIL_TEXT = {"no_reach": "به اتصال اولیه جواب نداد (بسته، فیلتر یا خاموش)",
             "no_traffic": "جواب داد ولی ترافیک واقعی ازش رد نشد (فیلتر عمیق یا محدودیت)",
             "tls": "گواهی TLS نامعتبر (احتمال شنود)", "tamper": "محتوای HTTP دستکاری شده بود"}


def new_stats():
    return {"runs": 0, "first": 0, "last": 0, "tested": 0, "reach": 0, "alive": 0, "blocked": 0,
            "unsupported": 0, "insecure": 0, "methods": {}, "ports": {}, "fails": {}}


def _cell():
    return {"tested": 0, "reach": 0, "alive": 0, "rescued": 0, "lat": [0, 0], "kbps": [0, 0]}


def add_run(st, cfgs, blocked=0, unsupported=0, insecure=0):
    """نتیجه‌ی یک اجرا رو به آمار اضافه می‌کنه. cfgs: کانفیگ‌های تست‌شده (دیکشنری‌های cfgscan)."""
    now = int(time.time())
    st["runs"] += 1
    st["first"] = st["first"] or now
    st["last"] = now
    st["blocked"] += blocked
    st["unsupported"] += unsupported
    st["insecure"] += insecure
    for c in cfgs:
        if not c.get("tested"):
            continue
        flags = c.get("flags") or set()
        cells = (st["methods"].setdefault(f"{c['proto']}/{c['network']}/{c['security']}", _cell()),
                 st["ports"].setdefault(str(c["port"]), _cell()))
        reach = bool(c.get("reachable"))
        working = bool(c.get("alive")) and not (flags & UNSAFE)
        st["tested"] += 1
        st["reach"] += reach
        for x in cells:
            x["tested"] += 1
            x["reach"] += reach
        if working:
            st["alive"] += 1
            for x in cells:
                x["alive"] += 1
                x["rescued"] += bool(c.get("variant"))
                if c.get("lat"):
                    x["lat"][0] += c["lat"]
                    x["lat"][1] += 1
                if c.get("kbps"):
                    x["kbps"][0] += c["kbps"]
                    x["kbps"][1] += 1
        else:
            why = ("no_reach" if not reach else "tls" if "tls_verify_fail" in flags
                   else "tamper" if "tamper" in flags else "no_traffic")
            st["fails"][why] = st["fails"].get(why, 0) + 1
    for k, cap in (("methods", 400), ("ports", 300)):  # سرور مخربی که روی همه‌ی پورت‌ها گوش می‌ده آمار و گزارش رو تا ابد بزرگ نکنه
        d = st[k]
        if len(d) > cap:
            for key in sorted(d, key=lambda z: d[z]["tested"])[:len(d) - cap]:
                del d[key]


def _ok_cell(x):
    try:
        return (isinstance(x, dict) and all(isinstance(x[f], (int, float)) for f in ("tested", "reach", "alive", "rescued"))
                and all(isinstance(x[f], list) and len(x[f]) == 2 and all(isinstance(v, (int, float)) for v in x[f])
                        for f in ("lat", "kbps")))
    except KeyError:
        return False


def load(path):
    try:
        st = json.loads(Path(path).read_text(encoding="utf-8"))
        if isinstance(st, dict) and isinstance(st.get("methods"), dict):
            st = {**new_stats(), **st}
            for k in ("methods", "ports"):
                st[k] = {a: b for a, b in (st[k].items() if isinstance(st[k], dict) else []) if isinstance(a, str) and _ok_cell(b)}
            st["fails"] = {a: b for a, b in (st["fails"].items() if isinstance(st["fails"], dict) else [])
                           if isinstance(a, str) and isinstance(b, int)}
            for k in ("runs", "tested", "reach", "alive", "blocked", "unsupported", "insecure", "first", "last"):
                if not isinstance(st.get(k), (int, float)):
                    st[k] = 0
            return st
    except Exception:
        pass
    return new_stats()


def save(path, st):
    try:
        Path(path).write_text(json.dumps(st), encoding="utf-8")
    except OSError:
        pass


def _row(key, x):
    return {"k": key, "tested": x["tested"], "reach": x["reach"], "alive": x["alive"], "rescued": x["rescued"],
            "rate": round(100 * x["alive"] / x["tested"]) if x["tested"] else 0,
            "ms": round(x["lat"][0] / x["lat"][1]) if x["lat"][1] else None,
            "mbps": round(x["kbps"][0] / x["kbps"][1] / 1000, 1) if x["kbps"][1] else None}


def table(cells, limit=None):
    rows = sorted((_row(k, v) for k, v in cells.items()), key=lambda r: (-r["alive"], -r["rate"], r["k"]))
    return rows[:limit] if limit else rows


def group(st, part):
    """جمع‌زدن روش‌ها بر اساس پروتکل (۰)، ترنسپورت (۱) یا امنیت (۲)."""
    agg = {}
    for key, x in st["methods"].items():
        if not (isinstance(key, str) and key.count("/") == 2 and _ok_cell(x)):  # آمار خراب/دستی‌ویرایش‌شده گزارش رو نمی‌اندازه
            continue
        a = agg.setdefault(key.split("/")[part], _cell())
        for f in ("tested", "reach", "alive", "rescued"):
            a[f] += x[f]
        for f in ("lat", "kbps"):
            a[f][0] += x[f][0]
            a[f][1] += x[f][1]
    return agg


def summary(st):
    return {"runs": st["runs"], "tested": st["tested"], "reach": st["reach"], "alive": st["alive"],
            "blocked": st["blocked"], "unsupported": st["unsupported"], "insecure": st["insecure"],
            "methods": table(st["methods"], 10)}


CSS = """body{font:14px/1.8 Tahoma,"Segoe UI",sans-serif;background:#fff;color:#1d2330;max-width:880px;margin:24px auto;padding:0 16px}
h1{font-size:20px}h2{font-size:16px;margin:26px 0 6px;border-bottom:1px solid #d9dee7;padding-bottom:4px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border-bottom:1px solid #e6e9ef;padding:4px 8px;text-align:right}
th{background:#f3f5f8}td.n{direction:ltr;text-align:center}.m{color:#5b6577;font-size:13px}.best{background:#eaf7f3}
code{direction:ltr;display:inline-block}@media print{body{margin:0}}"""


def _fmt(v, unit=""):
    return "—" if v is None else f"{v}{unit}"


def _tbl(rows, first="روش"):
    out = [f"<table><tr><th>{first}<th>تست‌شده<th>پاسخ‌دهنده<th>کارکرده<th>درصد موفقیت<th>میانگین پاسخ‌دهی<th>میانگین سرعت<th>با ترفند کمکی</tr>"]
    for r in rows:
        cls = ' class="best"' if r["alive"] and r is rows[0] else ""
        out.append(f"<tr{cls}><td><code>{html.escape(r['k'])}</code><td class=n>{r['tested']}<td class=n>{r['reach']}"
                   f"<td class=n><b>{r['alive']}</b><td class=n>{r['rate']}٪<td class=n>{_fmt(r['ms'], ' ms')}"
                   f"<td class=n>{_fmt(r['mbps'], ' Mbps')}<td class=n>{r['rescued']}</tr>")
    out.append("</table>")
    return "".join(out)


def _sum_line(st, title):
    when = (f"، از {time.strftime('%Y-%m-%d', time.localtime(st['first']))} تا {time.strftime('%Y-%m-%d', time.localtime(st['last']))}"
            if st["runs"] > 1 else "")
    rate = round(100 * st["alive"] / st["tested"]) if st["tested"] else 0
    return (f"<h2>{html.escape(title)}</h2><p>{st['runs']} اجرا{when}. کانفیگ تست‌شده: <b>{st['tested']}</b> | پاسخ‌دهنده: <b>{st['reach']}</b> | "
            f"کارکرده: <b>{st['alive']}</b> ({rate}٪)</p><p class=m>رد‌شده بدون تست: {st['blocked']} با فهرست سیاه امنیتی، "
            f"{st['unsupported']} پشتیبانی‌نشده، {st['insecure']} با تنظیم ناامن.</p>")


def render(run, cum):
    """گزارش کامل HTML. cum: همه‌ی اجراها، run: همین اجرای فعلی."""
    base = cum if cum["tested"] else run
    p = [f"<!doctype html><html lang=fa dir=rtl><meta charset=utf-8><title>گزارش روش‌ها</title><style>{CSS}</style>",
         "<h1>گزارش: چه کانفیگ‌هایی با چه روش‌هایی روی شبکه‌ی شما کار می‌کنن</h1>",
         f"<p class=m>ساخته‌شده در {time.strftime('%Y-%m-%d %H:%M')}. این گزارش فقط شمارنده‌ست؛ هیچ آدرس سرور، شناسه یا رمزی توش نیست.</p>"]
    top = [r for r in table(base["methods"]) if r["tested"] >= 5 and r["alive"]][:3]
    p.append("<h2>جمع‌بندی</h2>")
    if top:
        p.append("<p>بهترین روش‌ها روی شبکه‌ی شما (بر اساس تعداد کارکرده و درصد موفقیت):</p><ol>" + "".join(
            f"<li><code>{html.escape(r['k'])}</code>: {r['alive']} از {r['tested']} ({r['rate']}٪)"
            + (f"، سرعت میانگین {r['mbps']} Mbps" if r["mbps"] else "") + "</li>" for r in top) + "</ol>")
    else:
        p.append("<p>هنوز داده‌ی کافی نیست (حداقل ۵ تست برای هر روش لازمه). چند بار دیگه اجرا کن.</p>")
    if cum["runs"]:
        p.append(_sum_line(cum, "همه‌ی اجراها"))
        p.append(_tbl(table(cum["methods"])))
    p.append(_sum_line(run, "همین اجرا"))
    p.append(_tbl(table(run["methods"])) if run["methods"] else "<p class=m>در این اجرا هنوز تستی انجام نشده.</p>")
    for part, title in ((0, "به تفکیک پروتکل"), (1, "به تفکیک ترنسپورت"), (2, "به تفکیک امنیت")):
        g = group(base, part)
        if g:
            p.append(f"<h2>{title} (همه‌ی اجراها)</h2>" + _tbl(table(g), title.split()[-1]))
    if base["ports"]:
        p.append("<h2>پورت‌ها (۱۲ تای اول)</h2>" + _tbl(table(base["ports"], 12), "پورت"))
    if base["fails"]:
        tot = sum(base["fails"].values())
        p.append("<h2>چرا بقیه کار نکردن؟</h2><table><tr><th>دلیل<th>تعداد<th>درصد</tr>" + "".join(
            f"<tr><td>{html.escape(FAIL_TEXT.get(k, k))}<td class=n>{v}<td class=n>{round(100 * v / tot)}٪</tr>"
            for k, v in sorted(base["fails"].items(), key=lambda kv: -kv[1])) + "</table>")
    p.append("<h2>توضیح</h2><ul class=m><li><b>پاسخ‌دهنده:</b> به اتصال اولیه جواب داد. <b>کارکرده:</b> ترافیک واقعی ازش رد شد و مشکل امنیتی دیده نشد.</li>"
             "<li><b>با ترفند کمکی:</b> فقط وقتی روش ساده کار نکرد (fragment یا اثرانگشت دیگه‌ی TLS) و با اون وصل شد.</li>"
             "<li>تست‌ها از شبکه‌ی خودت انجام شده؛ بر اساس نمونه‌ی کانفیگ‌هایی بوده که به ترتیب تست شدن و ممکنه همه‌ی کانفیگ‌ها رو پوشش نده.</li>"
             "<li>کانفیگ‌های ذخیره‌شده‌ی قبلی (که از قبل سالم بودن) توی آمار حساب نمی‌شن تا نتیجه سوگیری نداشته باشه.</li></ul></html>")
    return "".join(p)
