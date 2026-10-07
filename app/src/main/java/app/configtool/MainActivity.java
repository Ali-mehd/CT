package app.configtool;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.webkit.DownloadListener;
import android.webkit.JavascriptInterface;
import android.webkit.JsResult;
import android.webkit.URLUtil;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;

/** رابط: یک WebView که همان ui.html را از سرور محلی (127.0.0.1) بارگذاری می‌کند. */
public class MainActivity extends Activity {
    private static final int REQ_VPN = 10, REQ_SAVE = 11;

    private WebView web;
    private TextView info;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean loaded;
    private byte[] pendingSave;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        info = new TextView(this);
        info.setTextColor(0xffe0e5ec);
        info.setBackgroundColor(0xff14181e);
        info.setTextSize(16);
        info.setPadding(48, 96, 48, 48);
        info.setText("در حال آماده‌سازی …");
        web = new WebView(this);
        web.setBackgroundColor(0xff14181e);
        web.setVisibility(android.view.View.GONE);
        android.widget.FrameLayout root = new android.widget.FrameLayout(this);
        root.addView(web);
        root.addView(info);
        setContentView(root);

        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setSupportMultipleWindows(false);
        if (Build.VERSION.SDK_INT >= 26) s.setSafeBrowsingEnabled(false); // آدرس محلی؛ چیزی به گوگل نرود
        web.addJavascriptInterface(new Bridge(), "AndroidBridge");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, String url) {
                String u = CoreService.url;
                return u == null || !url.startsWith(u.substring(0, u.indexOf("/?t="))); // فقط خود رابط محلی
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onJsConfirm(WebView v, String url, String msg, final JsResult r) {
                new AlertDialog.Builder(MainActivity.this).setMessage(msg)
                        .setPositiveButton("باشه", (d, w) -> r.confirm())
                        .setNegativeButton("نه", (d, w) -> r.cancel())
                        .setOnCancelListener(d -> r.cancel()).show();
                return true;
            }

            @Override
            public boolean onJsAlert(WebView v, String url, String msg, final JsResult r) {
                new AlertDialog.Builder(MainActivity.this).setMessage(msg)
                        .setPositiveButton("باشه", (d, w) -> r.confirm())
                        .setOnCancelListener(d -> r.confirm()).show();
                return true;
            }
        });
        web.setDownloadListener(new DownloadListener() {
            @Override
            public void onDownloadStart(String url, String ua, String cd, String mime, long len) {
                saveFile(url, URLUtil.guessFileName(url, cd, mime));
            }
        });

        if (Build.VERSION.SDK_INT >= 33) requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 1);
        startCore();
        ensureVpn();
        askBatteryOnce();
        waitForUi();
    }

    private void startCore() {
        Intent i = new Intent(this, CoreService.class);
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(i);
        else startService(i);
    }

    /** اجازه‌ی VPN (دیالوگ خود سیستم؛ بار اول). بدون آن فقط پروکسی محلی کار می‌کند. */
    void ensureVpn() {
        Intent i = VpnService.prepare(this);
        if (i != null) startActivityForResult(i, REQ_VPN);
    }

    private void waitForUi() {
        ui.postDelayed(new Runnable() {
            @Override
            public void run() {
                if (CoreService.error != null) {
                    info.setText("خطا در راه‌اندازی هسته:\n" + CoreService.error);
                    return;
                }
                String u = CoreService.url;
                if (u != null && !loaded) {
                    loaded = true;
                    info.setVisibility(android.view.View.GONE);
                    web.setVisibility(android.view.View.VISIBLE);
                    web.loadUrl(u);
                    return;
                }
                if (!loaded) ui.postDelayed(this, 150);
            }
        }, 150);
    }

    private void askBatteryOnce() {
        SharedPreferences p = getSharedPreferences("app", MODE_PRIVATE);
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (p.getBoolean("battery_asked", false) || pm.isIgnoringBatteryOptimizations(getPackageName())) return;
        p.edit().putBoolean("battery_asked", true).apply();
        new AlertDialog.Builder(this)
                .setMessage("برای اینکه اتصال وقتی از برنامه بیرون میری قطع نشه، اندروید باید اجازه بده برنامه بدون محدودیت باتری کار کنه. الان اجازه بدی؟")
                .setPositiveButton("باشه", (d, w) -> openBatterySettings())
                .setNegativeButton("بعداً", null).show();
    }

    private void openBatterySettings() {
        try {
            startActivity(new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + getPackageName())));
        } catch (Exception e) {
            try {
                startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS));
            } catch (Exception ignored) {
            }
        }
    }

    // ------------------------------------------------------------------ ذخیره‌ی گزارش (بدون نیاز به مجوز حافظه)
    private void saveFile(final String url, final String name) {
        new Thread(() -> {
            try {
                HttpURLConnection c = (HttpURLConnection) new java.net.URL(url).openConnection();
                c.setConnectTimeout(5000);
                c.setReadTimeout(15000);
                ByteArrayOutputStream bo = new ByteArrayOutputStream();
                try (InputStream in = c.getInputStream()) {
                    byte[] buf = new byte[16 * 1024];
                    int r;
                    while ((r = in.read(buf)) > 0 && bo.size() < 20_000_000) bo.write(buf, 0, r);
                }
                pendingSave = bo.toByteArray();
                ui.post(() -> {
                    Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                            .setType("text/html").putExtra(Intent.EXTRA_TITLE, name);
                    startActivityForResult(i, REQ_SAVE);
                });
            } catch (Exception e) {
                ui.post(() -> Toast.makeText(this, "ذخیره نشد", Toast.LENGTH_SHORT).show());
            }
        }).start();
    }

    @Override
    protected void onActivityResult(int req, int res, Intent data) {
        super.onActivityResult(req, res, data);
        if (req == REQ_VPN && res != RESULT_OK) {
            Toast.makeText(this, "بدون اجازه‌ی VPN فقط پروکسی محلی کار می‌کنه", Toast.LENGTH_LONG).show();
        } else if (req == REQ_SAVE && res == RESULT_OK && data != null && data.getData() != null && pendingSave != null) {
            try (OutputStream os = getContentResolver().openOutputStream(data.getData())) {
                os.write(pendingSave);
                Toast.makeText(this, "ذخیره شد", Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                Toast.makeText(this, "ذخیره نشد", Toast.LENGTH_SHORT).show();
            }
            pendingSave = null;
        }
    }

    @Override
    public void onBackPressed() {
        if (loaded && web.canGoBack()) web.goBack();
        else moveTaskToBack(true); // برنامه نبندد؛ اتصال در پس‌زمینه ادامه دارد
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacksAndMessages(null);
        web.destroy();
        super.onDestroy();
    }

    /** فقط به صفحه‌ی خود برنامه داده می‌شود (ناوبری به جای دیگه بسته است). */
    private final class Bridge {
        @JavascriptInterface
        public void moveToBack() {
            ui.post(() -> moveTaskToBack(true));
        }

        @JavascriptInterface
        public void batterySettings() {
            ui.post(MainActivity.this::openBatterySettings);
        }

        @JavascriptInterface
        public void ensureVpn() {
            ui.post(MainActivity.this::ensureVpn);
        }
    }
}
