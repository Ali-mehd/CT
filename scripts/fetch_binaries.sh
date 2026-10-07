#!/usr/bin/env bash
# دریافت xray، sing-box و hev-socks5-tunnel از انتشارهای رسمی GitHub، بررسی هش، و چیدن‌شان در پروژه.
# ورژن‌ها و SHA256 پین شده‌اند؛ اگه هش نخواند، ساخت متوقف می‌شود.
set -euo pipefail
cd "$(dirname "$0")/.."

XRAY_TAG=v26.3.27
XRAY_SHA=57149ffd48b629c07bf76938e73ab2729fde5910091497eab3e93d1c190f4c1b     # با فایل .dgst رسمی انتشار برابر است
SB_TAG=v1.14.2
SB_SHA=57eeb81867a9a5e406bcbb5f7fde352acdc354e8c084173a28bdd9417c5e0cba       # از دانلود مستقیم محاسبه شده (فایل رسمی هش ندارد)
HEV_TAG=2.18.0
HEV_SHA=15ec8ed121663b562c99caa5bb602d1009f24e5b09e733438b81988f12feaaab      # از دانلود مستقیم محاسبه شده

W=$(mktemp -d); trap "rm -rf $W" EXIT
J=app/src/main/jniLibs/arm64-v8a; A=app/src/main/assets/geo; L=app/libs
mkdir -p "$J" "$A" "$L"

get() { # url sha out
  curl -fL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null || { echo "هش نادرست: $1" >&2; exit 1; }
}

get "https://github.com/XTLS/Xray-core/releases/download/$XRAY_TAG/Xray-android-arm64-v8a.zip" "$XRAY_SHA" "$W/xray.zip"
unzip -oq "$W/xray.zip" -d "$W/x"
install -m755 "$W/x/xray" "$J/libxray.so"
cp "$W/x/geoip.dat" "$W/x/geosite.dat" "$A/"

get "https://github.com/SagerNet/sing-box/releases/download/$SB_TAG/sing-box-${SB_TAG#v}-android-arm64.tar.gz" "$SB_SHA" "$W/sb.tgz"
tar -xzf "$W/sb.tgz" -C "$W"
install -m755 "$W"/sing-box-*-android-arm64/sing-box "$J/libsingbox.so"

get "https://github.com/heiher/hev-socks5-tunnel/releases/download/$HEV_TAG/hev-socks5-tunnel.aar" "$HEV_SHA" "$W/hev.aar"
unzip -oq "$W/hev.aar" -d "$W/h"
install -m755 "$W/h/jni/arm64-v8a/libhev-socks5-tunnel.so" "$J/libhev-socks5-tunnel.so"
cp "$W/h/classes.jar" "$L/hev-tproxy.jar"

echo "آماده:"; ls -la "$J" "$A" "$L"
