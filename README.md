# ConfigTool برای اندروید

APK تک‌فایلی، arm64-v8a، minSdk 24. هسته‌ی پایتون (همان cfgweb.py) با Chaquopy داخل برنامه اجرا می‌شود؛
رابط یک WebView است که همان ui.html را از سرور محلی (127.0.0.1 با توکن) نشان می‌دهد.

## ساخت

### GitHub Actions (ساده‌ترین)
مخزن را روی GitHub بگذار، تب Actions، `build-apk`، Run workflow. خروجی: Artifact با نام `ConfigTool-apk`.
برای کلید ثابت (لازم برای به‌روزرسانی روی نسخه‌ی قبلی): `bash scripts/make_keystore.sh` را یک‌بار اجرا کن و
محتوای `release.keystore.b64` را در Secret با نام `KEYSTORE_B64` و رمز را در `KEYSTORE_PASSWORD` بگذار.
بدون Secret، یک کلید موقت ساخته می‌شود (نصب می‌شود ولی نسخه‌ی بعدی را باید حذف و دوباره نصب کنی).

### محلی
پیش‌نیاز: JDK 17، Android SDK (platform 34 و build-tools 34.0.0)، Python 3.13 (هم‌ورژن Chaquopy).
```
export ANDROID_HOME=$HOME/Android/Sdk
bash scripts/fetch_binaries.sh                 # xray, sing-box, hev (هش بررسی می‌شود)
bash scripts/make_keystore.sh release.keystore # یک‌بار
export KEYSTORE_FILE=$PWD/release.keystore KEYSTORE_PASSWORD=<رمز چاپ‌شده> KEY_ALIAS=key
./gradlew assembleRelease
adb install -r app/build/outputs/apk/release/app-release.apk
```

## تست پایتون روی کامپیوتر
`python3 tests/android_mode_test.py` (سرور در حالت اندروید، توکن/Host/Origin، API وضعیت، پورت تصادفی).

## تست روی گوشی (این مرحله هنوز انجام نشده)
۱) نصب و باز کردن: رابط بالا بیاد، دیالوگ اجازه‌ی VPN و اعلان بیاد.  ۲) اتصال با VPN روشن؛ بعد از «وصل شدی» آی‌پی را در
یک سایت آی‌پی‌یاب (در مرورگر گوشی) ببین.  ۳) رفتن به برنامه‌ی دیگر و خاموش‌کردن صفحه برای ۱۰ دقیقه؛ هنوز وصله؟
۴) «خروج کامل»: آیکون کلید VPN برود.  ۵) یک کانفیگ hysteria2/tuic را هم امتحان کن (sing-box).
لاگ: `adb logcat -d -s CfgCore python.stdout python.stderr AndroidRuntime`
