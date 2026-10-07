#!/usr/bin/env bash
# ساخت کلید امضا (فقط یک‌بار). بدون هیچ نام یا اطلاعات شخصی. خروجی: release.keystore + رمز
# برای GitHub Actions: محتوای release.keystore.b64 را در Secret با نام KEYSTORE_B64 و رمز را در KEYSTORE_PASSWORD بگذار.
set -euo pipefail
OUT=${1:-release.keystore}
PASS=${KEYSTORE_PASSWORD:-$(head -c 24 /dev/urandom | base64 | tr -dc A-Za-z0-9 | head -c 24)}
keytool -genkeypair -keystore "$OUT" -storepass "$PASS" -keypass "$PASS" -alias key \
  -dname "CN=ConfigTool" -keyalg RSA -keysize 2048 -validity 36500 >/dev/null 2>&1
base64 -w0 "$OUT" > "$OUT.b64"
echo "keystore: $OUT"; echo "KEYSTORE_PASSWORD=$PASS"
echo "این کلید را نگه دار: برای به‌روزرسانی APK باید با همین کلید امضا بشه. هیچ‌وقت آپلودش نکن."
