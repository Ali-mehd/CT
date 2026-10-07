package app.configtool;

import android.content.Context;
import android.content.res.AssetManager;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/** کپی فایل‌های assets به حافظه‌ی خصوصی برنامه (xray مسیر geoip/geosite را از روی دیسک می‌خواند). */
final class Assets {
    private Assets() {}

    /** force=false: فقط اگه فایل نبود یا اندازه‌اش فرق داشت (برای geoip/geosite که بزرگ‌اند). */
    static void copyDir(Context c, String assetDir, File dest, boolean force) throws IOException {
        AssetManager am = c.getAssets();
        String[] names = am.list(assetDir);
        if (names == null) return;
        if (!dest.isDirectory() && !dest.mkdirs()) throw new IOException("mkdir " + dest);
        for (String n : names) {
            File out = new File(dest, n);
            long size = -1;
            try (android.content.res.AssetFileDescriptor fd = am.openFd(assetDir + "/" + n)) {
                size = fd.getLength();
            } catch (IOException compressed) {
                // فایل فشرده‌شده openFd ندارد؛ پس با اندازه‌ی نامعلوم همیشه کپی می‌شود
            }
            if (!force && out.isFile() && size >= 0 && out.length() == size) continue;
            File tmp = new File(dest, n + ".tmp");
            try (InputStream in = am.open(assetDir + "/" + n); OutputStream os = new FileOutputStream(tmp)) {
                byte[] buf = new byte[64 * 1024];
                int r;
                while ((r = in.read(buf)) > 0) os.write(buf, 0, r);
            }
            if (out.exists() && !out.delete()) throw new IOException("delete " + out);
            if (!tmp.renameTo(out)) throw new IOException("rename " + tmp);
        }
    }
}
