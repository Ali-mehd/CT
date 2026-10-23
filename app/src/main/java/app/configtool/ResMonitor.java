package app.configtool;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Build;
import android.os.PowerManager;

import org.json.JSONObject;

/**
 * وضعیت واقعی گوشی (رم، دما، باتری، صرفه‌جویی، صفحه) را به‌صورت JSON برای کنترلر منابع پایتون (cfgres.py) جمع می‌کند.
 * هر مقداری که این گوشی/نسخه‌ی اندروید نمی‌دهد اصلاً در JSON نمی‌آید (پایتون «نامعلوم» را محدودیت حساب نمی‌کند).
 * هیچ مجوز اضافه‌ای لازم نیست و هیچ چیزی از گوشی بیرون نمی‌رود؛ خروجی فقط به پایتونِ داخل همین برنامه می‌رود.
 */
final class ResMonitor {
    private static long lastHeadroomMs;
    private static float lastHeadroom = -1f;

    private ResMonitor() {
    }

    static String collect(Context ctx, int trimLevel) {
        JSONObject o = new JSONObject();
        try {
            o.put("cores", Runtime.getRuntime().availableProcessors());
            ActivityManager am = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);
            if (am != null) {
                ActivityManager.MemoryInfo mi = new ActivityManager.MemoryInfo();
                am.getMemoryInfo(mi);
                o.put("ram_total_mb", mi.totalMem / (1024L * 1024L));
                o.put("ram_avail_mb", mi.availMem / (1024L * 1024L));
                o.put("low_mem", mi.lowMemory);
                o.put("low_ram", am.isLowRamDevice());
            }
            Intent b = ctx.registerReceiver(null, new IntentFilter(Intent.ACTION_BATTERY_CHANGED));
            if (b != null) {
                int lv = b.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
                int sc = b.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
                if (lv >= 0 && sc > 0) o.put("batt_pct", lv * 100.0 / sc);
                int t = b.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Integer.MIN_VALUE);
                if (t != Integer.MIN_VALUE) o.put("batt_temp_c", t / 10.0);
                o.put("charging", b.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) != 0);
            }
            PowerManager pm = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                if (Build.VERSION.SDK_INT >= 21) {
                    o.put("power_save", pm.isPowerSaveMode());
                    o.put("screen_on", pm.isInteractive());
                }
                if (Build.VERSION.SDK_INT >= 29) {
                    o.put("thermal", pm.getCurrentThermalStatus());
                }
                if (Build.VERSION.SDK_INT >= 30) {
                    long now = System.currentTimeMillis();
                    if (now - lastHeadroomMs >= 15000) { // این API نباید پشت‌سرهم صدا زده شود
                        lastHeadroomMs = now;
                        lastHeadroom = pm.getThermalHeadroom(10);
                    }
                    float h = lastHeadroom;
                    if (!Float.isNaN(h) && h >= 0f) o.put("headroom", h);
                }
            }
            o.put("trim", trimLevel);
        } catch (Throwable t) {
            // هر خطا = داده‌ی ناقص؛ پایتون با همان مقدارهای موجود کار می‌کند
        }
        return o.toString();
    }
}
