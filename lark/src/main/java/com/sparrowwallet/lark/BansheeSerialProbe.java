// Banshee additions to Lark. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * Detect Banshee firmware on a serial port without resetting unrelated COM devices.
 */
public final class BansheeSerialProbe {
    public static final int ESPRESSIF_VID = 0x303a;
    public static final int APP_PID = 0xb05e;
    public static final int BOOTLOADER_PID = 0x1001;
    private static final int BAUD = 115200;
    private static final int PROBE_TIMEOUT_MS = 1500;
    private static final int JADE_PID = 0x4001;
    private static final int OPEN_ATTEMPTS = 8;
    private static volatile boolean skip;
    private static SerialPort held;
    private static boolean reused;

    private BansheeSerialProbe() {
    }

    /** When true, Desktop will not open the Banshee COM port (Studio owns it). */
    public static void setSkip(boolean value) {
        skip = value;
    }

    public static List<SerialPort> findBootloaderPorts() {
        List<SerialPort> found = new ArrayList<>();
        for(SerialPort port : SerialPort.getCommPorts()) {
            int vid = port.getVendorID() & 0xFFFF;
            int pid = port.getProductID() & 0xFFFF;
            if(vid == ESPRESSIF_VID && pid == BOOTLOADER_PID) {
                found.add(port);
            }
        }
        return found;
    }

    public static String findBootloaderPortPath() {
        List<SerialPort> ports = findBootloaderPorts();
        if(ports.isEmpty()) {
            return null;
        }
        return pathOf(ports.get(0));
    }

    public static String findAppPortPath() {
        for(SerialPort port : SerialPort.getCommPorts()) {
            int vid = port.getVendorID() & 0xFFFF;
            int pid = port.getProductID() & 0xFFFF;
            if(vid == ESPRESSIF_VID && pid == APP_PID) {
                return pathOf(port);
            }
        }
        return null;
    }

    /** USB CDC if plugged, else BLE when a board was already selected. */
    public static String findPreferredPath() {
        String usb = findGatePortPath();
        if(usb != null && !usb.isBlank()) {
            return usb;
        }
        if(BansheeBle.hasTarget()) {
            return BansheeBle.pathOf(BansheeBle.selected());
        }
        return null;
    }

    /** Same matching Desktop USB scan uses (b05e first, then any Espressif CDC Lark would open). */
    public static String findGatePortPath() {
        String app = findAppPortPath();
        if(app != null && !app.isBlank()) {
            return app;
        }
        for(SerialPort port : SerialPort.getCommPorts()) {
            if(matches(port, true)) {
                return pathOf(port);
            }
        }
        return null;
    }

    public static boolean hasVidPid(SerialPort serialPort) {
        return BansheeClient.BANSHEE_DEVICE_IDS.stream().anyMatch(id -> id.matches(serialPort));
    }

    public static boolean matches(SerialPort serialPort) {
        return matches(serialPort, true);
    }

    public static boolean matches(SerialPort serialPort, boolean allowProbe) {
        if(skip) {
            return false;
        }
        if(hasVidPid(serialPort) || nameLooksLikeBanshee(serialPort)) {
            return true;
        }
        int vid = serialPort.getVendorID() & 0xFFFF;
        int pid = serialPort.getProductID() & 0xFFFF;
        if(vid == ESPRESSIF_VID && pid != JADE_PID) {
            return true;
        }
        return allowProbe && missingVidPid(serialPort) && looksLikeUsbCdc(serialPort)
                && probesBanner(serialPort);
    }

    public static void prepareSerialPort(SerialPort serialPort) {
        serialPort.clearDTR();
        serialPort.clearRTS();
    }

    /** True while the OS still enumerates this port, i.e. the device has not been unplugged. */
    public static boolean portPresent(String path) {
        if(path == null || path.isBlank()) {
            return false;
        }
        if(BansheeBle.isBlePath(path)) {
            return BansheeBle.supported();
        }
        for(SerialPort port : SerialPort.getCommPorts()) {
            if(samePortPath(pathOf(port), path)) {
                return true;
            }
        }
        return false;
    }

    public static boolean samePortPath(String a, String b) {
        if(a == null || b == null) {
            return false;
        }
        if(a.equals(b)) {
            return true;
        }
        return normalizePortPath(a).equalsIgnoreCase(normalizePortPath(b));
    }

    public static String normalizePortPath(String path) {
        String p = path.trim();
        if(p.startsWith("\\\\.\\")) {
            p = p.substring(4);
        } else if(p.startsWith("//./")) {
            p = p.substring(4);
        }
        return p;
    }

    /**
     * Open the Banshee CDC port. Reuses a live handle so Sign does not reopen after
     * fingerprint — jSerialComm closePort drops DTR and Windows then reports COM gone (error 2).
     */
    public static synchronized SerialPort openReady(SerialPort requested) throws DeviceException {
        if(requested == null) {
            throw new DeviceException("No Banshee serial port");
        }
        String path = pathOf(requested);
        if(path == null || path.isBlank()) {
            throw new DeviceException("Banshee serial port has no system path");
        }

        reused = false;
        if(held != null && held.isOpen() && samePortPath(pathOf(held), path) && portPresent(path)) {
            reused = true;
            return held;
        }
        // A handle kept across a replug stays isOpen() but no longer reaches the device.
        quietlyClose(held);
        held = null;

        int lastCode = 0;
        for(int attempt = 1; attempt <= OPEN_ATTEMPTS; attempt++) {
            for(String tryPath : candidatePaths(path)) {
                SerialPort port = SerialPort.getCommPort(tryPath);
                port.setComPortParameters(BAUD, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
                port.setFlowControl(SerialPort.FLOW_CONTROL_DISABLED);
                port.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 400, 0);
                boolean opened = port.openPort(200);
                lastCode = port.getLastErrorCode();
                if(opened && port.isOpen()) {
                    sleep(200);
                    if(port.isOpen()) {
                        held = port;
                        return port;
                    }
                }
                quietlyClose(port);
            }
            sleep(lastCode == 2 ? 1500 : 400 + (attempt * 150));
        }
        throw new DeviceException(openFailedMessage(path, lastCode));
    }

    public static synchronized boolean wasReused() {
        return reused;
    }

    public static synchronized void invalidate() {
        quietlyClose(held);
        held = null;
        reused = false;
    }

    private static void quietlyClose(SerialPort port) {
        if(port != null && port.isOpen()) {
            port.closePort();
        }
    }

    private static String pathOf(SerialPort serialPort) {
        String path = serialPort.getSystemPortPath();
        if(path == null || path.isBlank()) {
            path = serialPort.getSystemPortName();
        }
        return path;
    }

    private static List<String> candidatePaths(String requested) {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        addPathForms(paths, requested);
        for(SerialPort p : SerialPort.getCommPorts()) {
            if(!hasVidPid(p) && !nameLooksLikeBanshee(p)) {
                continue;
            }
            addPathForms(paths, pathOf(p));
        }
        return new ArrayList<>(paths);
    }

    private static void addPathForms(LinkedHashSet<String> paths, String path) {
        if(path == null || path.isBlank()) {
            return;
        }
        String n = normalizePortPath(path);
        paths.add(n);
        paths.add("\\\\.\\" + n);
    }

    private static String openFailedMessage(String path, int code) {
        String hint = "Close Banshee Desktop if it is using the cable, then unplug and replug.";
        if(code == 5 || code == 32) {
            return "Could not open Banshee serial port " + path + " (in use). " + hint;
        }
        if(code == 2) {
            return "Could not open Banshee serial port " + path + " (device disappeared). Unplug and replug the Banshee, then try Sign again.";
        }
        return "Could not open Banshee serial port " + path + (code != 0 ? " (error " + code + ")" : "") + ". " + hint;
    }

    private static boolean missingVidPid(SerialPort serialPort) {
        int vid = serialPort.getVendorID() & 0xFFFF;
        int pid = serialPort.getProductID() & 0xFFFF;
        return vid == 0 || vid == 0xFFFF || pid == 0 || pid == 0xFFFF;
    }

    private static boolean nameLooksLikeBanshee(SerialPort serialPort) {
        String text = portText(serialPort);
        return text.contains("banshee") || text.contains("lilygo") || text.contains("t-display")
                || text.contains("esp32") || text.contains("jtag");
    }

    private static boolean looksLikeUsbCdc(SerialPort serialPort) {
        String text = portText(serialPort);
        if(text.contains("bluetooth") || text.contains("bth") || text.contains("com0com")) {
            return false;
        }
        return text.contains("usb") || text.contains("serial") || text.contains("jtag") || text.contains("ch340") || text.contains("cp210") || text.contains("silicon");
    }

    private static String portText(SerialPort serialPort) {
        StringBuilder sb = new StringBuilder();
        if(serialPort.getDescriptivePortName() != null) {
            sb.append(serialPort.getDescriptivePortName()).append(' ');
        }
        if(serialPort.getPortDescription() != null) {
            sb.append(serialPort.getPortDescription()).append(' ');
        }
        if(serialPort.getSystemPortName() != null) {
            sb.append(serialPort.getSystemPortName());
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    public static boolean probesBanner(SerialPort serialPort) {
        boolean openedHere = false;
        int priorBaud = serialPort.getBaudRate();
        try {
            prepareSerialPort(serialPort);
            if(!serialPort.isOpen()) {
                serialPort.setBaudRate(BAUD);
                serialPort.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING, 400, 0);
                if(!serialPort.openPort(0)) {
                    return false;
                }
                openedHere = true;
            }
            InputStream in = serialPort.getInputStream();
            long deadline = System.currentTimeMillis() + PROBE_TIMEOUT_MS;
            while(System.currentTimeMillis() < deadline) {
                String line = readLine(in, 200);
                if(line.isEmpty()) {
                    continue;
                }
                if(line.contains("banshee-gate")) {
                    return true;
                }
                if(line.startsWith("OK ") || line.startsWith("ERR ")) {
                    return line.contains("banshee") || line.startsWith("OK PONG") || line.startsWith("OK READY") || line.startsWith("OK INFO") || line.startsWith("OK WALLET");
                }
            }
            return false;
        } catch(IOException e) {
            return false;
        } finally {
            if(openedHere && serialPort.isOpen()) {
                serialPort.closePort();
            }
            serialPort.setBaudRate(priorBaud);
        }
    }

    public static void sleep(int ms) {
        try {
            Thread.sleep(ms);
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static String readLine(InputStream in, int timeoutMs) throws IOException {
        List<Byte> buf = new ArrayList<>();
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline) {
            if(in.available() > 0) {
                int b = in.read();
                if(b < 0) {
                    break;
                }
                if(b == '\r') {
                    continue;
                }
                if(b == '\n') {
                    return new String(toBytes(buf), StandardCharsets.UTF_8).trim();
                }
                if(buf.size() < 256) {
                    buf.add((byte)b);
                }
            } else {
                sleep(5);
            }
        }
        return "";
    }

    private static byte[] toBytes(List<Byte> bytes) {
        byte[] arr = new byte[bytes.size()];
        for(int i = 0; i < bytes.size(); i++) {
            arr[i] = bytes.get(i);
        }
        return arr;
    }
}
