// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Windows BLE helper process. Speaks the same newline protocol as USB CDC.
 */
public final class BansheeBle {
    public static final String PATH = "ble";
    private static final String RESOURCE = "/com/sparrowwallet/lark/native/banshee-ble.exe";
    private static final Object LOCK = new Object();
    private static volatile Process process;
    private static volatile Process scanProc;
    private static volatile InputStream in;
    private static volatile OutputStream out;
    private static volatile boolean connected;
    private static volatile String lastError = "";
    private static Path nativeDir;
    private static volatile Advertised selected;

    private BansheeBle() {
    }

    public static synchronized void useDirectory(File dir) {
        nativeDir = dir == null ? null : dir.toPath();
    }

    public record Advertised(String name, String address, String type) {
        public String path() {
            return PATH + ":" + address;
        }

        @Override
        public String toString() {
            String label = name == null || name.isBlank() ? "Banshee" : name.trim();
            return label + "  (" + address + ")";
        }
    }

    public static boolean isBlePath(String path) {
        if(path == null) {
            return false;
        }
        String p = path.trim().toLowerCase(Locale.ROOT);
        return p.equals(PATH) || p.startsWith(PATH + ":");
    }

    public static boolean hasTarget() {
        return selected != null;
    }

    public static Advertised selected() {
        return selected;
    }

    public static void select(Advertised advertised) {
        selected = advertised;
    }

    public static void selectFromPath(String path) {
        if(!isBlePath(path)) {
            return;
        }
        int colon = path.indexOf(':');
        if(colon < 0 || colon + 1 >= path.length()) {
            return;
        }
        String address = path.substring(colon + 1).trim().toUpperCase(Locale.ROOT);
        if(address.isBlank()) {
            return;
        }
        if(selected != null && address.equalsIgnoreCase(selected.address())) {
            return;
        }
        selected = new Advertised("Banshee", address, "Unspecified");
    }

    public static String pathOf(Advertised advertised) {
        return advertised == null ? PATH : advertised.path();
    }

    public static boolean supported() {
        return File.pathSeparatorChar == ';' && exeFile().isFile();
    }

    public static boolean alive() {
        Process p = process;
        return p != null && p.isAlive();
    }

    public static boolean connected() {
        return alive() && connected;
    }

    public static List<Advertised> scan() throws DeviceException {
        File exe = exeFile();
        if(!exe.isFile()) {
            throw new DeviceException("Banshee Bluetooth helper is missing.");
        }
        ProcessBuilder pb = new ProcessBuilder(exe.getAbsolutePath(), "scan");
        pb.redirectErrorStream(false);
        Process started;
        try {
            started = pb.start();
        } catch(IOException e) {
            throw new DeviceException("Could not start Bluetooth scan", e);
        }
        Process previousScan;
        synchronized(LOCK) {
            previousScan = scanProc;
            scanProc = started;
        }
        kill(previousScan);
        List<Advertised> found = new ArrayList<>();
        try(BufferedReader reader = new BufferedReader(new InputStreamReader(started.getInputStream(), StandardCharsets.UTF_8))) {
            drainStderr(started.getErrorStream());
            String line;
            while((line = reader.readLine()) != null) {
                Advertised row = parseScanLine(line);
                if(row != null) {
                    found.add(row);
                }
            }
            if(!started.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)) {
                kill(started);
                throw new DeviceException("Bluetooth scan timed out.");
            }
            if(started.exitValue() != 0 && found.isEmpty()) {
                throw new DeviceException(lastError.isBlank()
                        ? "Bluetooth scan failed."
                        : lastError);
            }
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            kill(started);
            throw new DeviceException("Bluetooth scan interrupted.");
        } catch(IOException e) {
            kill(started);
            throw new DeviceException("Bluetooth scan failed", e);
        } finally {
            synchronized(LOCK) {
                if(scanProc == started) {
                    scanProc = null;
                }
            }
        }
        return found;
    }

    public static void connectSelected() throws DeviceException {
        DeviceException last = null;
        for(int attempt = 0; attempt < 3; attempt++) {
            try {
                attach(new BansheeGate.Streams());
                return;
            } catch(DeviceException e) {
                last = e;
                invalidate();
                try {
                    Thread.sleep(400L * (attempt + 1));
                } catch(InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
        throw last;
    }

    public static void markConnected() {
        if(alive()) {
            connected = true;
        }
    }

    public static void attach(BansheeGate.Streams streams) throws DeviceException {
        synchronized(LOCK) {
            if(alive() && connected) {
                streams.in = in;
                streams.out = out;
                streams.ble = true;
                return;
            }
        }
        invalidate();
        File exe = exeFile();
        if(!exe.isFile()) {
            throw new DeviceException("Banshee Bluetooth helper is missing.");
        }
        lastError = "";
        List<String> cmd = new ArrayList<>();
        cmd.add(exe.getAbsolutePath());
        Advertised target = selected;
        if(target != null && target.address() != null && !target.address().isBlank()) {
            cmd.add("connect");
            cmd.add(target.address());
            if(target.type() != null && !target.type().isBlank()) {
                cmd.add(target.type());
            }
        }
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        Process started;
        try {
            started = pb.start();
        } catch(IOException e) {
            throw new DeviceException("Could not start Banshee Bluetooth", e);
        }
        synchronized(LOCK) {
            process = started;
            in = started.getInputStream();
            out = started.getOutputStream();
            connected = false;
        }
        drainStderr(started.getErrorStream());
        try {
            waitConnected(started, 60000);
        } catch(DeviceException e) {
            invalidate();
            throw e;
        }
        synchronized(LOCK) {
            if(process != started || !alive() || !connected) {
                throw new DeviceException("Bluetooth reset.");
            }
            streams.in = in;
            streams.out = out;
            streams.ble = true;
        }
    }

    public static void invalidate() {
        Process helper;
        Process scan;
        synchronized(LOCK) {
            helper = process;
            scan = scanProc;
            process = null;
            scanProc = null;
            in = null;
            out = null;
            connected = false;
        }
        kill(helper);
        kill(scan);
    }

    /** Kill the helper and drop the remembered board so Scan can start immediately. */
    public static void forget() {
        selected = null;
        invalidate();
    }

    private static void kill(Process p) {
        if(p == null || !p.isAlive()) {
            return;
        }
        p.destroy();
        try {
            if(!p.waitFor(400, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                p.destroyForcibly();
                p.waitFor(400, java.util.concurrent.TimeUnit.MILLISECONDS);
            }
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
            p.destroyForcibly();
        }
    }

    private static Advertised parseScanLine(String line) {
        if(line == null || line.isBlank()) {
            return null;
        }
        String[] parts = line.split("\t");
        if(parts.length < 2) {
            return null;
        }
        String name = parts[0].trim();
        String address = parts[1].trim().toUpperCase(Locale.ROOT);
        String type = parts.length >= 3 ? parts[2].trim() : "Unspecified";
        if(address.isBlank()) {
            return null;
        }
        return new Advertised(name, address, type);
    }

    private static void waitConnected(Process started, int timeoutMs) throws DeviceException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline) {
            if(process != started || !started.isAlive()) {
                throw new DeviceException(lastError.isBlank()
                        ? "Bluetooth reset."
                        : lastError);
            }
            if("connected".equalsIgnoreCase(lastError.trim())) {
                connected = true;
                return;
            }
            String err = lastError.trim();
            if(!err.isEmpty() && !"scanning".equalsIgnoreCase(err) && !"connecting".equalsIgnoreCase(err)
                    && started.isAlive() && err.toLowerCase(Locale.ROOT).contains("timed out")) {
                throw new DeviceException(err);
            }
            try {
                Thread.sleep(40);
            } catch(InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new DeviceException("Bluetooth reset.");
            }
        }
        throw new DeviceException(lastError.isBlank()
                ? "No Banshee Bluetooth device. Stay close and turn the computer Bluetooth on."
                : lastError);
    }

    private static void drainStderr(InputStream err) {
        Thread t = new Thread(() -> {
            StringBuilder line = new StringBuilder();
            try {
                int b;
                while((b = err.read()) >= 0) {
                    if(b == '\n') {
                        lastError = line.toString().trim();
                        line.setLength(0);
                    } else if(b != '\r') {
                        line.append((char)b);
                    }
                }
            } catch(IOException ignored) {
            }
        }, "banshee-ble-err");
        t.setDaemon(true);
        t.start();
    }

    private static File exeFile() {
        Path packaged = Path.of(System.getProperty("java.home"), "lib", "banshee-ble.exe");
        if(Files.isRegularFile(packaged)) {
            return packaged.toFile();
        }
        Path dir = nativeDir;
        if(dir == null) {
            String home = System.getProperty("banshee.native.dir");
            dir = home == null || home.isBlank()
                    ? Path.of(System.getProperty("user.home"), "AppData", "Roaming", "Banshee Light", "native")
                    : Path.of(home);
        }
        try {
            BansheeSecureFiles.ownerOnlyDir(dir);
            Path exe = dir.resolve("banshee-ble.exe");
            byte[] bundled = readBundledExe();
            if(bundled.length == 0) {
                return exe.toFile();
            }
            byte[] want = BansheeSecureFiles.sha256(bundled);
            if(Files.isRegularFile(exe)) {
                byte[] have = BansheeSecureFiles.sha256(Files.readAllBytes(exe));
                if(BansheeSecureFiles.sameSha256(want, have)) {
                    return exe.toFile();
                }
                if(alive()) {
                    return exe.toFile();
                }
            }
            Files.write(exe, bundled);
            BansheeSecureFiles.ownerOnly(exe);
            return exe.toFile();
        } catch(IOException e) {
            return new File("banshee-ble.exe");
        }
    }

    private static byte[] readBundledExe() {
        try(InputStream in = BansheeBle.class.getResourceAsStream(RESOURCE)) {
            if(in == null) {
                return new byte[0];
            }
            return in.readAllBytes();
        } catch(IOException e) {
            return new byte[0];
        }
    }
}
