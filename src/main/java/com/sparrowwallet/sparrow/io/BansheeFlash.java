// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.drongo.OsType;
import com.sparrowwallet.lark.BansheeSerialProbe;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * USB flash of bundled Banshee firmware via bundled espflash (no Python).
 * Unsigned path is for new unfused chips. Signed path uses a Studio RSA-3072 .pem.
 */
public final class BansheeFlash {
    private static final Logger log = LoggerFactory.getLogger(BansheeFlash.class);
    private static final String[] BINS = {"bootloader.bin", "partitions.bin", "firmware.bin"};
    private static final int[] OFFSETS = {0x0, 0x8000, 0x10000};
    private static final int APP0_OFFSET = 0x10000;
    private static final int APP1_OFFSET = 0x650000;
    private static final int NVS_OFFSET = 0x9000;
    private static final int NVS_SIZE = 0x5000;

    private BansheeFlash() {
    }

    public static String bundledVersion() {
        try(InputStream in = BansheeFlash.class.getResourceAsStream("/firmware/manifest.json")) {
            if(in == null) {
                return "";
            }
            String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
            int key = json.indexOf("\"version\"");
            int colon = key < 0 ? -1 : json.indexOf(':', key);
            int q1 = colon < 0 ? -1 : json.indexOf('"', colon + 1);
            int q2 = q1 < 0 ? -1 : json.indexOf('"', q1 + 1);
            return q2 < 0 ? "" : json.substring(q1 + 1, q2).trim();
        } catch(IOException e) {
            return "";
        }
    }

    public static String flashUnsigned(Consumer<String> onLog) throws ImportException {
        BansheeSerialProbe.invalidate();
        String app = BansheeSerialProbe.findAppPortPath();
        if(app != null && !app.isBlank()) {
            logLine(onLog, "Firmware still running. Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader PID 1001…");
        }
        Path dir;
        Path espflash;
        try {
            dir = extractFirmware();
            espflash = extractEspflash();
        } catch(IOException e) {
            throw new ImportException("Could not unpack bundled flash tools: " + e.getMessage(), e);
        }
        List<Write> writes = new ArrayList<>();
        for(int i = 0; i < BINS.length; i++) {
            writes.add(new Write(dir.resolve(BINS[i]), OFFSETS[i]));
        }
        logLine(onLog, "Writing unsigned firmware with bundled espflash…");
        return flashWrites(espflash, writes, onLog);
    }

    /**
     * Sign bundled firmware.bin with {@code pem} and write both app slots.
     * Does not touch bootloader, partitions, or otadata — a fused chip's ROM-verified
     * bootloader must stay as Studio wrote it.
     */
    public static String flashSigned(Path pem, Consumer<String> onLog) throws ImportException {
        BansheeSerialProbe.invalidate();
        if(BansheeSerialProbe.findAppPortPath() != null) {
            logLine(onLog, "Firmware still running. Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader PID 1001…");
        }
        Path dir;
        Path espflash;
        try {
            dir = extractFirmware();
            espflash = extractEspflash();
            logLine(onLog, "Signing firmware.bin with " + pem.getFileName() + " (app slots only, bootloader unchanged)…");
            Path signedFw = dir.resolve("firmware-signed.bin");
            Files.write(signedFw, EspSecureBootV2.sign(Files.readAllBytes(dir.resolve("firmware.bin")), pem));
            signedFw.toFile().deleteOnExit();
            List<Write> writes = List.of(
                    new Write(signedFw, APP0_OFFSET),
                    new Write(signedFw, APP1_OFFSET)
            );
            String path = flashWrites(espflash, writes, onLog);
            if(path == null || path.isBlank()) {
                throw new ImportException(
                        "Flash wrote, but the board did not come back as Banshee (b05e). Unplug without LEFT. If the screen stays blank, recover in Studio: Choose the original .pem → Full reflash. Light does not rewrite the bootloader.");
            }
            return path;
        } catch(IOException e) {
            throw new ImportException("Could not sign or unpack firmware: " + e.getMessage(), e);
        }
    }

    /**
     * Erase NVS (lock + seed) then write bundled firmware.
     * Signed path keeps the Studio bootloader; unsigned erases the chip first.
     */
    public static String flashFull(Path pem, Consumer<String> onLog) throws ImportException {
        BansheeSerialProbe.invalidate();
        if(BansheeSerialProbe.findAppPortPath() != null) {
            logLine(onLog, "Firmware still running. Unplug, hold LEFT (BOOT), plug in. Waiting for bootloader PID 1001…");
        }
        Path dir;
        Path espflash;
        try {
            dir = extractFirmware();
            espflash = extractEspflash();
        } catch(IOException e) {
            throw new ImportException("Could not unpack bundled flash tools: " + e.getMessage(), e);
        }
        String portPath = requireBootloader(onLog);
        String port = normalizePort(portPath);
        logLine(onLog, "Bootloader port " + port);
        if(pem == null) {
            logLine(onLog, "Full flash: erase chip, then write unsigned bootloader + partitions + firmware…");
            eraseFlash(espflash, port, onLog);
            List<Write> writes = new ArrayList<>();
            for(int i = 0; i < BINS.length; i++) {
                writes.add(new Write(dir.resolve(BINS[i]), OFFSETS[i]));
            }
            return flashWritesOnPort(espflash, port, writes, onLog);
        }
        try {
            logLine(onLog, "Full flash: erase NVS (lock + wallet), then sign and write both app slots…");
            eraseNvs(espflash, port, onLog);
            Path signedFw = dir.resolve("firmware-signed.bin");
            Files.write(signedFw, EspSecureBootV2.sign(Files.readAllBytes(dir.resolve("firmware.bin")), pem));
            signedFw.toFile().deleteOnExit();
            List<Write> writes = List.of(
                    new Write(signedFw, APP0_OFFSET),
                    new Write(signedFw, APP1_OFFSET)
            );
            String path = flashWritesOnPort(espflash, port, writes, onLog);
            if(path == null || path.isBlank()) {
                throw new ImportException(
                        "Flash wrote, but the board did not come back as Banshee (b05e). Unplug without LEFT.");
            }
            return path;
        } catch(IOException e) {
            throw new ImportException("Could not sign or unpack firmware: " + e.getMessage(), e);
        }
    }

    private static String flashWrites(Path espflash, List<Write> writes, Consumer<String> onLog) throws ImportException {
        String portPath = requireBootloader(onLog);
        String port = normalizePort(portPath);
        logLine(onLog, "Bootloader port " + port);
        return flashWritesOnPort(espflash, port, writes, onLog);
    }

    private static String flashWritesOnPort(Path espflash, String port, List<Write> writes, Consumer<String> onLog)
            throws ImportException {
        String[] befores = {"no-reset", "usb-reset"};
        for(int i = 0; i < writes.size(); i++) {
            Write w = writes.get(i);
            boolean last = i == writes.size() - 1;
            int code = -1;
            String[] tryBefore = i == 0 ? befores : new String[] {"no-reset"};
            for(String before : tryBefore) {
                List<String> cmd = writeBinCommand(espflash, port, w.file, w.offset, before, last);
                logLine(onLog, "Flash " + w.file.getFileName() + " @ 0x" + Integer.toHexString(w.offset)
                        + " (" + before + ", no-stub, 115200)");
                code = run(cmd, onLog);
                if(code == 0) {
                    break;
                }
                if(i == 0 && before.equals("no-reset")) {
                    logLine(onLog, "Retry with USB-JTAG reset…");
                }
            }
            if(code != 0) {
                throw new ImportException("Flash failed writing " + w.file.getFileName() + " (exit " + code
                        + "). Close Light USB scans, hold LEFT, unplug/replug, try Flash again.");
            }
        }
        logLine(onLog, "Flash done. Waiting for app USB (PID b05e)…");
        return waitForAppPort(onLog);
    }

    private static void eraseFlash(Path espflash, String port, Consumer<String> onLog) throws ImportException {
        List<String> cmd = eraseCommand(espflash, port, "erase-flash");
        logLine(onLog, "Erase entire flash (NVS lock + wallet + firmware)…");
        int code = run(cmd, onLog);
        if(code != 0) {
            throw new ImportException("erase-flash failed (exit " + code + "). Hold LEFT, unplug/replug, try Full flash again.");
        }
    }

    private static void eraseNvs(Path espflash, String port, Consumer<String> onLog) throws ImportException {
        List<String> cmd = eraseCommand(espflash, port, "erase-region");
        cmd.add("0x" + Integer.toHexString(NVS_OFFSET));
        cmd.add("0x" + Integer.toHexString(NVS_SIZE));
        logLine(onLog, "Erase NVS @ 0x" + Integer.toHexString(NVS_OFFSET)
                + " size 0x" + Integer.toHexString(NVS_SIZE) + " (lock + wallet)…");
        int code = run(cmd, onLog);
        if(code != 0) {
            throw new ImportException("erase-region NVS failed (exit " + code + "). Hold LEFT, unplug/replug, try Full flash again.");
        }
    }

    private static List<String> eraseCommand(Path espflash, String port, String sub) {
        List<String> cmd = new ArrayList<>();
        cmd.add(espflash.toString());
        cmd.add("--skip-update-check");
        cmd.add(sub);
        cmd.add("--non-interactive");
        cmd.add("--no-stub");
        cmd.add("--chip");
        cmd.add("esp32s3");
        cmd.add("-p");
        cmd.add(port);
        cmd.add("-B");
        cmd.add("115200");
        cmd.add("-b");
        cmd.add("usb-reset");
        cmd.add("-a");
        cmd.add("no-reset");
        return cmd;
    }

    private static String requireBootloader(Consumer<String> onLog) throws ImportException {
        String portPath = BansheeSerialProbe.findBootloaderPortPath();
        if(portPath != null && !portPath.isBlank()) {
            return portPath;
        }
        logLine(onLog, "No bootloader yet. Hold LEFT (BOOT), unplug 3 seconds, plug in.");
        long deadline = System.currentTimeMillis() + 90000;
        while(System.currentTimeMillis() < deadline) {
            portPath = BansheeSerialProbe.findBootloaderPortPath();
            if(portPath != null && !portPath.isBlank()) {
                return portPath;
            }
            BansheeSerialProbe.sleep(500);
        }
        throw new ImportException("No T-Display S3 bootloader (USB PID 1001). Hold LEFT (BOOT), plug in USB, then try again.");
    }

    static String normalizePort(String path) {
        String p = path.trim();
        if(p.startsWith("\\\\.\\")) {
            return p.substring(4);
        }
        if(p.startsWith("//./")) {
            return p.substring(4);
        }
        return p;
    }

    private static List<String> writeBinCommand(Path espflash, String port, Path file, int offset,
            String before, boolean last) {
        List<String> cmd = new ArrayList<>();
        cmd.add(espflash.toString());
        cmd.add("--skip-update-check");
        cmd.add("write-bin");
        cmd.add("--non-interactive");
        cmd.add("--no-stub");
        cmd.add("--chip");
        cmd.add("esp32s3");
        cmd.add("-p");
        cmd.add(port);
        cmd.add("-B");
        cmd.add("115200");
        cmd.add("-b");
        cmd.add(before);
        cmd.add("-a");
        cmd.add(last ? "hard-reset" : "no-reset");
        cmd.add("0x" + Integer.toHexString(offset));
        cmd.add(file.toString());
        return cmd;
    }

    private static String waitForAppPort(Consumer<String> onLog) throws ImportException {
        long deadline = System.currentTimeMillis() + 30000;
        while(System.currentTimeMillis() < deadline) {
            String path = BansheeSerialProbe.findAppPortPath();
            if(path != null && !path.isBlank()) {
                logLine(onLog, "Banshee app port " + path);
                return path;
            }
            BansheeSerialProbe.sleep(500);
        }
        logLine(onLog, "App port not seen yet — unplug and replug if needed (do not hold LEFT).");
        return "";
    }

    private static Path extractFirmware() throws IOException {
        Path dir = Files.createTempDirectory("banshee-fw");
        dir.toFile().deleteOnExit();
        for(String name : BINS) {
            try(InputStream in = BansheeFlash.class.getResourceAsStream("/firmware/" + name)) {
                if(in == null) {
                    throw new IOException("Missing bundled firmware file " + name);
                }
                Path out = dir.resolve(name);
                Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
                out.toFile().deleteOnExit();
            }
        }
        return dir;
    }

    private static Path extractEspflash() throws IOException {
        boolean windows = OsType.getCurrent() == OsType.WINDOWS;
        String name = windows ? "espflash.exe" : "espflash";
        Path bundled = Path.of(System.getProperty("java.home", ""), "lib", name);
        if(Files.isRegularFile(bundled)) {
            return bundled;
        }
        String[] resources = windows
                ? new String[] {"/flash/espflash.exe", "/native/windows/x64/espflash.exe"}
                : new String[] {"/flash/espflash-linux", "/native/linux/x64/espflash"};
        IOException last = new IOException("Missing bundled " + name);
        for(String resource : resources) {
            try(InputStream in = BansheeFlash.class.getResourceAsStream(resource)) {
                if(in == null) {
                    continue;
                }
                Path out = Files.createTempFile("banshee-", "-" + name);
                Files.copy(in, out, StandardCopyOption.REPLACE_EXISTING);
                out.toFile().deleteOnExit();
                if(!windows) {
                    try {
                        Files.setPosixFilePermissions(out, EnumSet.of(
                                PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE,
                                PosixFilePermission.GROUP_READ, PosixFilePermission.GROUP_EXECUTE,
                                PosixFilePermission.OTHERS_READ, PosixFilePermission.OTHERS_EXECUTE));
                    } catch(UnsupportedOperationException ignored) {
                    }
                }
                return out;
            } catch(IOException e) {
                last = e;
            }
        }
        throw last;
    }

    private static int run(List<String> cmd, Consumer<String> onLog) {
        try {
            Process process = new ProcessBuilder(cmd).redirectErrorStream(true).start();
            try(BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while((line = reader.readLine()) != null) {
                    logLine(onLog, line);
                }
            }
            if(!process.waitFor(5, TimeUnit.MINUTES)) {
                process.destroyForcibly();
                return -1;
            }
            return process.exitValue();
        } catch(Exception e) {
            log.error("espflash failed", e);
            logLine(onLog, e.getMessage());
            return -1;
        }
    }

    private static void logLine(Consumer<String> onLog, String msg) {
        if(onLog != null) {
            onLog.accept(msg);
        }
        log.info(msg);
    }

    private record Write(Path file, int offset) {
    }
}
