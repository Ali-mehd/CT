package app.configtool;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.util.Log;

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;

import hev.htproxy.TProxyService;

/**
 * سرویس اصلی: هسته‌ی پایتون را بالا می‌آورد، با اعلان در پیش‌زمینه می‌ماند و وقتی اتصال برقرار شد
 * TUN می‌سازد و ترافیک را با hev-socks5-tunnel به SOCKS5 محلی می‌دهد.
 * خود برنامه از VPN مستثناست (addDisallowedApplication) تا ترافیک xray/sing-box به خودش برنگردد.
 */
public class CoreService extends VpnService {
    private static final String TAG = "CfgCore";
    private static final String CHANNEL = "core";
    private static final int NOTIF_ID = 1;
    private static final String MAPDNS = "198.18.0.2";

    /** آدرس رابط (با توکن)؛ MainActivity منتظرش می‌ماند. */
    static volatile String url;
    static volatile String error;

    private volatile boolean stopping;
    private Thread monitor;
    private PowerManager.WakeLock wakeLock;
    private PyObject mod;

    private ParcelFileDescriptor tun;
    private int tunSocks;
    private Thread tproxyThread;
    private boolean revoked;
    private String lastNotif = "";

    @Override
    public void onCreate() {
        super.onCreate();
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel ch = new NotificationChannel(CHANNEL, "اتصال", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).createNotificationChannel(ch);
        }
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIF_ID, buildNotif("در حال آماده‌سازی …"));
        if (wakeLock == null) {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "configtool:core");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire();
        }
        if (monitor == null) {
            monitor = new Thread(this::run, "core-monitor");
            monitor.start();
        }
        return START_NOT_STICKY; // اگه سیستم کشتش، بدون رابط دوباره بالا نیاد
    }

    @Override
    public void onRevoke() {
        // کاربر VPN را از تنظیمات سیستم قطع کرد؛ تا قطع/اتصال بعدی دوباره نساز
        revoked = true;
        closeTun();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopping = true;
        closeTun();
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        super.onDestroy();
    }

    // ------------------------------------------------------------------ حلقه‌ی اصلی
    private void run() {
        try {
            File data = new File(getFilesDir(), "data");
            File web = new File(getFilesDir(), "web");
            File geo = new File(getFilesDir(), "geo");
            File cache = new File(getCacheDir(), "tmp");
            cache.mkdirs();
            Assets.copyDir(this, "web", web, true);
            Assets.copyDir(this, "geo", geo, false);
            if (!Python.isStarted()) Python.start(new AndroidPlatform(this));
            mod = Python.getInstance().getModule("cfgandroid");
            url = mod.callAttr("start", data.getAbsolutePath(), web.getAbsolutePath(), geo.getAbsolutePath(),
                    getApplicationInfo().nativeLibraryDir, cache.getAbsolutePath()).toString();
        } catch (Throwable t) {
            Log.e(TAG, "start failed", t);
            error = String.valueOf(t);
            return;
        }
        while (!stopping) {
            try {
                tick();
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                return;
            } catch (Throwable t) {
                Log.e(TAG, "tick", t);
            }
        }
    }

    private void tick() throws Exception {
        JSONObject st = new JSONObject(mod.callAttr("status").toString());
        String stage = st.optString("stage");
        boolean want = st.optBoolean("want");
        int socks = st.optInt("socks");
        boolean connected = "connected".equals(stage);
        boolean busy = connected || "running".equals(stage);
        if (!busy) revoked = false;

        boolean up = tun != null;
        if (!want || !busy || revoked) {
            if (up) closeTun();
        } else if (connected && !up) {
            openTun(socks);
        } else if (up && socks != tunSocks && connected) {
            closeTun(); // پورت SOCKS عوض شد (xray دوباره بالا اومد)؛ تونل را با پورت جدید بساز
            openTun(socks);
        }
        // «running» وقتی TUN بالاست: عمداً نگه می‌داریم تا وسط تعویض سرور ترافیک بی‌تونل بیرون نره
        boolean on = tun != null && tproxyThread != null && TProxyService.TProxyIsRunning();
        mod.callAttr("set_vpn", on);
        notifyText(on ? "VPN سراسری فعاله" : connected ? "اتصال برقرار (فقط پروکسی محلی)" : busy ? "در حال اتصال …" : "آماده");
    }

    // ------------------------------------------------------------------ TUN
    private void openTun(int socks) {
        if (VpnService.prepare(this) != null) { // اجازه‌ی VPN هنوز داده نشده
            Log.w(TAG, "VPN permission missing");
            revoked = true;
            return;
        }
        try {
            Builder b = new Builder().setSession("ConfigTool").setMtu(1500)
                    .addAddress("198.18.0.1", 32).addRoute("0.0.0.0", 0)
                    .addAddress("fc00::1", 128).addRoute("::", 0)
                    .addDnsServer(MAPDNS);
            b.addDisallowedApplication(getPackageName());
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            tun = b.establish();
            if (tun == null) {
                revoked = true;
                return;
            }
            tunSocks = socks;
            File cfg = new File(getFilesDir(), "tproxy.yml");
            String y = "tunnel:\n  mtu: 1500\n  ipv4: 198.18.0.1\n  ipv6: \u0027fc00::1\u0027\n"
                    + "socks5:\n  port: " + socks + "\n  address: 127.0.0.1\n  udp: \u0027udp\u0027\n"
                    + "mapdns:\n  address: " + MAPDNS + "\n  port: 53\n  network: 100.64.0.0\n  netmask: 255.192.0.0\n  cache-size: 10000\n"
                    + "misc:\n  log-level: warn\n";
            try (FileOutputStream os = new FileOutputStream(cfg)) {
                os.write(y.getBytes(StandardCharsets.UTF_8));
            }
            final int fd = tun.getFd();
            final String path = cfg.getAbsolutePath();
            tproxyThread = new Thread(() -> {
                try {
                    TProxyService.TProxyStartService(path, fd);
                } catch (Throwable t) {
                    Log.e(TAG, "tproxy", t);
                }
            }, "tproxy");
            tproxyThread.start();
            // اگه تا ۳ ثانیه بالا نیومد، تونل را رها کن (وگرنه ترافیک گوشی در سیاه‌چاله می‌افته)
            for (int i = 0; i < 30 && !TProxyService.TProxyIsRunning(); i++) Thread.sleep(100);
            if (!TProxyService.TProxyIsRunning()) {
                Log.e(TAG, "tproxy did not start");
                revoked = true;
                closeTun();
            }
        } catch (Throwable t) {
            Log.e(TAG, "openTun", t);
            revoked = true;
            closeTun();
        }
    }

    private void closeTun() {
        try {
            if (tproxyThread != null) {
                TProxyService.TProxyStopService();
                tproxyThread.join(2000);
            }
        } catch (Throwable t) {
            Log.w(TAG, "stop tproxy", t);
        }
        tproxyThread = null;
        try {
            if (tun != null) tun.close();
        } catch (Throwable ignored) {
        }
        tun = null;
    }

    // ------------------------------------------------------------------ اعلان
    private Notification buildNotif(String text) {
        Intent open = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        int fl = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, fl);
        Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
        return nb.setContentTitle("ConfigTool").setContentText(text).setSmallIcon(R.drawable.ic_stat)
                .setContentIntent(pi).setOngoing(true).build();
    }

    private void notifyText(String text) {
        if (text.equals(lastNotif)) return;
        lastNotif = text;
        ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).notify(NOTIF_ID, buildNotif(text));
    }
}
