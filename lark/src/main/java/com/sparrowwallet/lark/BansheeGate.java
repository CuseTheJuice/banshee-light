// Banshee additions to Lark. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import com.fazecast.jSerialComm.SerialPort;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Text line protocol for Banshee firmware (USB CDC or BLE UART).
 */
public class BansheeGate implements AutoCloseable {
    private static final int DEFAULT_TIMEOUT_MS = 5000;
    private static final int SIGN_WAIT_TIMEOUT_MS = 30000;
    private static final int SIGN_TIMEOUT_MS = 180000;
    private static final int BUTTON_TIMEOUT_MS = 180000;
    private static final int COMMIT_ROLL_TIMEOUT_MS = 600000;
    private static final int ROLL_WORD_TIMEOUT_MS = 30000;
    private static final int PING_TIMEOUT_MS = 1200;
    private static final int BLE_PING_TIMEOUT_MS = 4000;
    private static final int PING_ATTEMPTS = 3;
    private static final int MAX_LINE = 65536;
    private static final int USB_WRITE_CHUNK = 64;
    private static final int BLE_WRITE_CHUNK = 180;

    private SerialPort serialPort;
    private InputStream in;
    private OutputStream out;
    private boolean ble;
    private final String network;

    static final class Streams {
        InputStream in;
        OutputStream out;
        boolean ble;
    }

    public BansheeGate(SerialPort requestedPort, String network) throws DeviceException {
        this(requestedPort == null ? BansheeBle.PATH : requestedPort.getSystemPortPath(), network);
    }

    public BansheeGate(String path, String network) throws DeviceException {
        this.network = network;
        if(BansheeBle.isBlePath(path)) {
            BansheeBle.selectFromPath(path);
            openBle();
            return;
        }
        this.serialPort = SerialPort.getCommPort(path);
        attach(BansheeSerialProbe.openReady(this.serialPort));
        try {
            handshake(BansheeSerialProbe.wasReused());
            return;
        } catch(IOException | DeviceException e) {
            // Opening a native USB CDC port can reset the board, and a kept-open session goes
            // dead across a replug. Either way one clean reopen beats asking the user to unplug.
            BansheeSerialProbe.invalidate();
        }
        try {
            attach(BansheeSerialProbe.openReady(this.serialPort));
            handshake(false);
        } catch(IOException | DeviceException e) {
            BansheeSerialProbe.invalidate();
            if(e instanceof DeviceException deviceException) {
                throw deviceException;
            }
            throw new DeviceException("Banshee serial error", e);
        }
    }

    private void openBle() throws DeviceException {
        DeviceException last = null;
        for(int attempt = 0; attempt < 3; attempt++) {
            try {
                attachBle(false);
                return;
            } catch(IOException | DeviceException e) {
                last = e instanceof DeviceException d ? d : new DeviceException("Banshee Bluetooth error", e);
                BansheeSerialProbe.sleep(300 * (attempt + 1));
            }
        }
        try {
            attachBle(true);
        } catch(IOException | DeviceException e) {
            BansheeBle.invalidate();
            if(e instanceof DeviceException deviceException) {
                throw deviceException;
            }
            throw last != null ? last : new DeviceException("Banshee Bluetooth error", e);
        }
    }

    private void attachBle(boolean force) throws IOException, DeviceException {
        if(force) {
            BansheeBle.invalidate();
        }
        boolean reused = BansheeBle.alive();
        Streams streams = new Streams();
        BansheeBle.attach(streams);
        this.in = streams.in;
        this.out = streams.out;
        this.ble = true;
        handshake(reused);
        BansheeBle.markConnected();
    }

    private void attach(SerialPort port) {
        this.serialPort = port;
        this.in = port.getInputStream();
        this.out = port.getOutputStream();
    }

    /** A reused port answers at once; a just-enumerated CDC port can need seconds to talk. */
    private void handshake(boolean reused) throws IOException, DeviceException {
        if(reused) {
            command("PING");
            return;
        }
        drainBanner();
        DeviceException last = null;
        for(int attempt = 1; attempt <= PING_ATTEMPTS; attempt++) {
            try {
                ping(ble ? BLE_PING_TIMEOUT_MS : PING_TIMEOUT_MS);
                return;
            } catch(DeviceException e) {
                if(!isTimeout(e)) {
                    throw e;
                }
                last = e;
                BansheeSerialProbe.sleep(400 * attempt);
            }
        }
        throw last;
    }

    private void ping(int timeoutMs) throws IOException, DeviceException {
        flushInput();
        writeCommand("PING");
        parseOk(readCommandLine(timeoutMs));
    }

    private static boolean isTimeout(DeviceException e) {
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase().contains("timeout");
    }

    private void drainBanner() throws IOException {
        long deadline = System.currentTimeMillis() + 800;
        while(System.currentTimeMillis() < deadline) {
            String line = readLine(250);
            if(line.isEmpty()) {
                continue;
            }
            if(line.startsWith("OK READY")) {
                return;
            }
            if(line.startsWith("OK ") || line.startsWith("ERR ")) {
                return;
            }
        }
    }

    public String command(String cmd) throws DeviceException {
        try {
            flushInput();
            writeCommand(cmd);
            String resp = readCommandLine(DEFAULT_TIMEOUT_MS);
            return parseOk(resp);
        } catch(IOException e) {
            throw new DeviceException("Banshee command failed: " + cmd, e);
        }
    }

    public String signPsbt(String psbtBase64) throws DeviceException {
        try {
            String compact = psbtBase64 == null ? "" : psbtBase64.replaceAll("\\s+", "");
            if(compact.length() < 16) {
                throw new DeviceException("bad PSBT");
            }
            flushInput();
            writeCommand("SIGN_PSBT " + network);
            parseOk(readResponseLine(DEFAULT_TIMEOUT_MS));
            final int chunk = 128;
            int sent = 0;
            while(sent < compact.length()) {
                int end = Math.min(sent + chunk, compact.length());
                writeCommand("SIGN_CHUNK " + compact.substring(sent, end));
                String ack = parseOk(readResponseLine(DEFAULT_TIMEOUT_MS));
                if(!ack.startsWith("CHUNK ")) {
                    throw new DeviceException("Unexpected Banshee chunk response: " + ack);
                }
                sent = end;
            }
            writeCommand("SIGN_END");
            String wait = readResponseLine(SIGN_WAIT_TIMEOUT_MS);
            parseOk(wait);
            if(!wait.contains("WAIT")) {
                throw new DeviceException("Unexpected Banshee sign response: " + wait);
            }
            String signed = readResponseLine(SIGN_TIMEOUT_MS);
            if(signed.startsWith("ERR ")) {
                if(signed.contains("timeout")) {
                    throw new DeviceException("Signing timed out on Banshee (unlock, match the Studio code, then press the right button to approve)");
                }
                throw new DeviceException(signed.substring(4));
            }
            return parseOkPrefix(signed, "PSBT ");
        } catch(IOException e) {
            throw new DeviceException("Banshee sign failed", e);
        }
    }

    private void writeCommand(String cmd) throws IOException {
        byte[] data = (cmd + "\n").getBytes(StandardCharsets.UTF_8);
        int chunk = ble ? BLE_WRITE_CHUNK : USB_WRITE_CHUNK;
        int off = 0;
        while(off < data.length) {
            int n = Math.min(chunk, data.length - off);
            out.write(data, off, n);
            out.flush();
            off += n;
            if(data.length > 256) {
                BansheeSerialProbe.sleep(2);
            }
        }
    }

    public String getFingerprint() throws DeviceException {
        return parseOkPrefix(command("GET_FINGERPRINT"), "FINGERPRINT ");
    }

    public String getXpub(String path) throws DeviceException {
        String normalized = path.replace('\'', 'h');
        return parseOkPrefix(command("GET_XPUB " + network + " " + normalized), "XPUB ");
    }

    public String showAddress(String address) throws DeviceException {
        try {
            flushInput();
            writeCommand("SHOW_ADDRESS " + address);
            String wait = readResponseLine(DEFAULT_TIMEOUT_MS);
            parseOk(wait);
            if(!wait.contains("WAIT")) {
                throw new DeviceException("Unexpected Banshee address response: " + wait);
            }
            String shown = readResponseLine(70000);
            if(shown.startsWith("ERR ")) {
                if(shown.contains("timeout")) {
                    throw new DeviceException("Address confirm timed out on Banshee (press the right button)");
                }
                throw new DeviceException(shown.substring(4));
            }
            return parseOkPrefix(shown, "SHOWN ");
        } catch(IOException e) {
            throw new DeviceException("Banshee address display failed", e);
        }
    }

    public String getEntropyProof() throws DeviceException {
        return parseOkPrefix(command("GET_ENTROPY_PROOF"), "PROOF ");
    }

    public String getRngHealth() throws DeviceException {
        return parseOkPrefix(command("GET_RNG_HEALTH"), "RNG ");
    }

    public BansheeInfo getInfo() throws DeviceException {
        return BansheeInfo.parse(parseOkPrefix(command("GET_INFO"), "INFO "));
    }

    public BansheeWalletStatus walletStatus() throws DeviceException {
        return BansheeWalletStatus.parse(parseOkPrefix(command("WALLET_STATUS"), "WALLET "));
    }

    public BansheeUnlockStatus unlockStatus() throws DeviceException {
        return BansheeUnlockStatus.parse(command("UNLOCK_STATUS"));
    }

    public BansheeUnlockStatus setUnlock() throws DeviceException {
        try {
            flushInput();
            writeCommand("SET_UNLOCK");
            String wait = readResponseLine(DEFAULT_TIMEOUT_MS);
            parseOk(wait);
            if(wait.contains("WAIT")) {
                String done = readResponseLine(BUTTON_TIMEOUT_MS);
                return finishOracle(done);
            }
            return finishOracle(wait);
        } catch(IOException e) {
            throw new DeviceException("Banshee command failed: SET_UNLOCK", e);
        }
    }

    public BansheeUnlockStatus setOracle(String url, String pubkeyHex) throws DeviceException {
        String u = BansheeOracle.normalize(url);
        String pub = pubkeyHex == null ? "" : pubkeyHex.trim().toLowerCase();
        if(pub.startsWith("0x")) {
            pub = pub.substring(2);
        }
        if(u.isEmpty() || pub.length() != 66) {
            throw new DeviceException("bad oracle");
        }
        String rest = command("SET_ORACLE " + u + " " + pub);
        if(!rest.startsWith("ORACLE ")) {
            throw new DeviceException("Unexpected Banshee response: " + rest);
        }
        return unlockStatus();
    }

    public BansheeUnlockStatus unlockOracle() throws DeviceException {
        try {
            flushInput();
            writeCommand("UNLOCK_ORACLE");
            String first = readResponseLine(DEFAULT_TIMEOUT_MS);
            String rest = parseOk(first.startsWith("OK ") || first.startsWith("ERR ") ? first : "OK " + first);
            if(rest.startsWith("UNLOCK")) {
                return BansheeUnlockStatus.parse(rest);
            }
            if(rest.contains("WAIT")) {
                String done = readResponseLine(BUTTON_TIMEOUT_MS);
                return finishOracle(done);
            }
            return finishOracle(first);
        } catch(IOException e) {
            throw new DeviceException("Banshee command failed: UNLOCK_ORACLE", e);
        }
    }

    private String followHostLine(String line, int timeoutMs) throws DeviceException, IOException {
        String raw = line == null ? "" : line.trim();
        if(raw.startsWith("ERR ")) {
            throw new DeviceException(parseOk(raw));
        }
        String rest = parseOk(raw.startsWith("OK ") || raw.startsWith("ERR ") ? raw : "OK " + raw);
        if(rest.startsWith("WAIT")) {
            return followHostLine(readResponseLine(timeoutMs), timeoutMs);
        }
        if(rest.startsWith("HTTP POST ") || rest.startsWith("HTTP ")) {
            BansheeOracle.HttpAsk ask = BansheeOracle.HttpAsk.parse(rest);
            String reply;
            try {
                reply = BansheeOracle.post(ask.url(), ask.dataB64());
            } catch(DeviceException e) {
                try {
                    writeCommand("CANCEL");
                    readResponseLine(DEFAULT_TIMEOUT_MS);
                } catch(Exception ignored) {
                }
                throw e;
            }
            writeCommand("ORACLE_REPLY " + reply);
            return followHostLine(readResponseLine(timeoutMs), timeoutMs);
        }
        return rest;
    }

    private BansheeUnlockStatus finishOracle(String line) throws DeviceException, IOException {
        String rest = followHostLine(line, BUTTON_TIMEOUT_MS);
        if(rest.startsWith("UNLOCK")) {
            return BansheeUnlockStatus.parse(rest);
        }
        throw new DeviceException("Unexpected Banshee response: " + rest);
    }

    public void rollCancel() throws DeviceException {
        try {
            command("ROLL_CANCEL");
        } catch(DeviceException e) {
            // Device may already be idle.
        }
    }

    public int rollBegin(int wordCount) throws DeviceException {
        int n = Math.max(1, Math.min(BansheeEntropyProof.WALLET_DICE_WORDS, wordCount));
        String rest = buttonCommand("ROLL_BEGIN " + n, "ROLL_BEGIN ", BUTTON_TIMEOUT_MS);
        int got = Integer.parseInt(rest.trim());
        if(got != n) {
            throw new DeviceException("Gate roll word count mismatch");
        }
        return n;
    }

    public BansheeRollWord rollWord() throws DeviceException {
        try {
            flushInput();
            writeCommand("ROLL_WORD");
            String resp = readResponseLine(ROLL_WORD_TIMEOUT_MS);
            return BansheeRollWord.parse(parseOkPrefix(resp.startsWith("OK ") ? resp : "OK " + resp, "DICE "));
        } catch(IOException e) {
            throw new DeviceException("ROLL_WORD failed", e);
        }
    }

    public BansheeRollAttestation rollProve() throws DeviceException {
        String rest = command("ROLL_PROVE");
        if(rest.startsWith("PROVE ")) {
            return BansheeRollAttestation.parse(rest.substring(6));
        }
        if(rest.contains("WAIT")) {
            try {
                String prove = readResponseLine(BUTTON_TIMEOUT_MS);
                return BansheeRollAttestation.parse(parseOkPrefix(prove.startsWith("OK ") ? prove : "OK " + prove, "PROVE "));
            } catch(IOException e) {
                throw new DeviceException("ROLL_PROVE failed", e);
            }
        }
        return BansheeRollAttestation.parse(rest);
    }

    public BansheeWalletStatus walletCommitRoll() throws DeviceException {
        String rest = buttonCommand("WALLET_COMMIT_ROLL", "WALLET ", COMMIT_ROLL_TIMEOUT_MS);
        return BansheeWalletStatus.parse(rest);
    }

    public String cloneExport() throws DeviceException {
        return buttonCommand("CLONE_EXPORT", "CLONE ", BUTTON_TIMEOUT_MS).trim();
    }

    public String backupWrap() throws DeviceException {
        return parseOkPrefix(command("BACKUP_WRAP"), "BACKUP_WRAP ").trim();
    }

    public void backupWrapSet(String hex) throws DeviceException {
        String key = hex == null ? "" : hex.trim().toLowerCase();
        if(key.length() != 64) {
            throw new DeviceException("bad backup wrap");
        }
        parseOk(command("BACKUP_WRAP_SET " + key));
    }

    public BansheeWalletStatus cloneImport(String payload) throws DeviceException {
        String blob = payload == null ? "" : payload.trim();
        if(blob.length() < 16) {
            throw new DeviceException("bad clone payload");
        }
        String rest = buttonCommand("CLONE_IMPORT " + blob, "WALLET ", BUTTON_TIMEOUT_MS);
        return BansheeWalletStatus.parse(rest);
    }

    public BansheeWalletStatus walletDelete() throws DeviceException {
        String rest = buttonCommand("WALLET_DELETE", "WALLET ", BUTTON_TIMEOUT_MS);
        return BansheeWalletStatus.parse(rest);
    }

    private String buttonCommand(String cmd, String successPrefix, int timeoutMs) throws DeviceException {
        try {
            flushInput();
            writeCommand(cmd);
            String rest = followHostLine(readResponseLine(DEFAULT_TIMEOUT_MS), timeoutMs);
            if(rest.startsWith(successPrefix)) {
                return rest.substring(successPrefix.length());
            }
            throw new DeviceException("Unexpected Banshee response: " + rest);
        } catch(IOException e) {
            throw new DeviceException("Banshee command failed: " + cmd, e);
        }
    }

    private static boolean isStrayStatus(String line) {
        return line.startsWith("OK READY")
                || line.startsWith("OK PONG")
                || line.startsWith("OK GOT");
    }

    private String readCommandLine(int timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline) {
            String line = readLine((int)Math.max(50, deadline - System.currentTimeMillis()));
            if(!line.isEmpty()) {
                return line;
            }
        }
        return "";
    }

    private String readResponseLine(int timeoutMs) throws IOException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while(System.currentTimeMillis() < deadline) {
            String line = readLine((int)Math.max(50, deadline - System.currentTimeMillis()));
            if(line.isEmpty()) {
                continue;
            }
            if(isStrayStatus(line)) {
                continue;
            }
            return line;
        }
        return "";
    }

    private void flushInput() throws IOException {
        while(in.available() > 0) {
            in.read();
        }
    }

    private static String parseOk(String line) throws DeviceException {
        if(line.startsWith("ERR ")) {
            String err = line.substring(4);
            if("locked".equals(err)) {
                throw new DeviceException("Unlock the Banshee with the side-button sequence, then try again.");
            }
            if("oracle_session".equals(err)) {
                throw new DeviceException("Keep Light connected and enter the sequence if asked. The lock screen can be clear while the oracle session is still closed.");
            }
            if(err.startsWith("pin")) {
                throw new DeviceException("Wrong unlock sequence. " + BansheeUnlockStatus.parse(err).remainingTries());
            }
            if("oracle_net".equals(err)) {
                throw new DeviceException(BansheeOracle.NET_MESSAGE);
            }
            if("oracle_setup".equals(err)) {
                throw new DeviceException("Set unlock again so this wallet can register with Light's oracle.");
            }
            if("oracle_url".equals(err)) {
                throw new DeviceException("Set unlock in Banshee Light so this device can register with Light's oracle.");
            }
            if("wiped".equals(err)) {
                throw new DeviceException("Three wrong sequences. The wallet on this device was erased.");
            }
            if("rejected".equals(err)) {
                throw new DeviceException("Rejected on the Banshee (left button).");
            }
            throw new DeviceException(err);
        }
        if(!line.startsWith("OK ")) {
            throw new DeviceException(line.isEmpty() ? "Banshee timeout" : line);
        }
        return line.substring(3);
    }

    private static String parseOkPrefix(String line, String prefix) throws DeviceException {
        String rest = parseOk(line.startsWith("OK ") ? line : "OK " + line);
        if(!rest.startsWith(prefix)) {
            throw new DeviceException("Unexpected Banshee response: " + line);
        }
        return rest.substring(prefix.length()).trim();
    }

    private String readLine(int timeoutMs) throws IOException {
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
                if(buf.size() < MAX_LINE) {
                    buf.add((byte)b);
                }
            } else {
                try {
                    Thread.sleep(5);
                } catch(InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
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

    @Override
    public void close() {
        // Keep the USB CDC or BLE session. closePort() drops DTR; Windows then reports COM gone.
    }
}
