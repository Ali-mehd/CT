#!/usr/bin/env python3
"""ساخت کلید امضای ثابت برای APK (فقط یک‌بار)، بدون JDK. نیاز: pip install cryptography

اجرا:   python scripts/make_keystore.py
خروجی:  release.keystore (نگه دار؛ هیچ‌جا آپلودش نکن) + دو مقدار برای GitHub:
        Settings ← Secrets and variables ← Actions ← New repository secret
          KEYSTORE_B64      = محتوای خط «KEYSTORE_B64=...»
          KEYSTORE_PASSWORD = رمزی که چاپ شد
با همین دو Secret، همه‌ی بیلدهای بعدی با یک امضا ساخته می‌شن و APK جدید روی قبلی نصب می‌شه (بدون حذف)."""
import base64
import datetime
import secrets
import string
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

out = sys.argv[1] if len(sys.argv) > 1 else "release.keystore"
pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(24))
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ConfigTool")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=36500)).sign(key, hashes.SHA256()))
# رمزنگاری سازگار با JDK 8+ و AGP (PBEWithSHA1And3-KeyTripleDES / SHA1 MAC)؛ فرمت پیش‌فرض جدید cryptography برای ابزارهای قدیمی‌تر مشکل‌ساز می‌شه
enc = (serialization.PrivateFormat.PKCS12.encryption_builder().kdf_rounds(50000)
       .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).hmac_hash(hashes.SHA1()).build(pw.encode()))
data = pkcs12.serialize_key_and_certificates(b"key", key, cert, None, enc)
open(out, "wb").write(data)
print(f"keystore: {out}")
print(f"KEYSTORE_PASSWORD={pw}")
print("KEYSTORE_B64=" + base64.b64encode(data).decode())
print("این فایل و رمز را نگه دار: برای به‌روزرسانی APK باید همیشه با همین کلید امضا بشه. هیچ‌وقت آپلودشان نکن.")
