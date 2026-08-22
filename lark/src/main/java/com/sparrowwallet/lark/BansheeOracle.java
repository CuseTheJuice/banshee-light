// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Blind oracle hosted by Banshee Light. Firmware still emits {@code HTTP POST};
 * Light answers in-process (no Studio, no Bearer token).
 */
public final class BansheeOracle {
    /** Placeholder URL stored on the device so the gate protocol still has a host. Never fetched. */
    public static final String DEVICE_URL = "http://127.0.0.1";
    /** Loopback HTTP for Studio BLE. USB still answers in-process. */
    public static final int LOOPBACK_PORT = 18457;
    public static final String NET_MESSAGE =
            "Light could not complete the oracle request. This is not a wrong sequence. If this board was set up on another Light, Restore the original backup on this PC first.";
    private static final int PIN_LEN = 32;
    private static final int ENT_LEN = 32;
    private static final int PUB_LEN = 33;
    private static final int SIG_LEN = 64;
    private static final int CKE_LEN = 33;
    private static final int CTR_LEN = 4;
    private static final int IV_LEN = 12;
    private static final int TAG_LEN = 16;
    private static final int PLAIN_LEN = PIN_LEN + ENT_LEN + PUB_LEN + SIG_LEN;
    private static final int WIRE_LEN = CKE_LEN + CTR_LEN + IV_LEN + PLAIN_LEN + TAG_LEN;
    private static final int RESP_PLAIN_LEN = 1 + 32 + 1;
    private static final int MAX_FAILS = 3;
    private static final byte[] LABEL_REQ = "banshee_oracle_request".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_RESP = "banshee_oracle_response".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] LABEL_STORE = "banshee_oracle_store".getBytes(StandardCharsets.US_ASCII);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final SecureRandom RNG = new SecureRandom();
    private static final Pattern DEVICE_ID = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern PUB_HEX = Pattern.compile("^[0-9a-f]{66}$|^[0-9a-f]{130}$");

    private static Path root;
    private static byte[] restoreShare;
    private static final String PENDING_WRAP_ID = "f".repeat(64);

    private BansheeOracle() {
    }

    public static synchronized void useDirectory(File dir) {
        restoreShare = null;
        if(dir == null) {
            root = null;
            return;
        }
        root = dir.toPath();
    }

    public static synchronized void listenLoopback() {
        // In-process post() is the oracle. Do not bind HTTP.
    }

    public static synchronized void stop() {
    }

    public static String normalize(String url) {
        if(url == null) {
            return "";
        }
        return url.trim().replaceAll("/+$", "");
    }

    public static String pubkey() throws DeviceException {
        return loadKey().pub;
    }

    /** Local oracle pubkey. URL argument is ignored (Light is the oracle). */
    public static String fetchPubkey(String ignoredBaseUrl) throws DeviceException {
        return pubkey();
    }

    public static String post(String url, String dataB64) throws DeviceException {
        String path = url == null ? "" : url.toLowerCase(Locale.ROOT);
        String kind;
        if(path.contains("/api/oracle/set_pin")) {
            kind = "set_pin";
        } else if(path.contains("/api/oracle/get_pin")) {
            kind = "get_pin";
        } else {
            throw new DeviceException(NET_MESSAGE);
        }
        Result out = handle(kind, dataB64);
        if(out.data == null || out.data.isEmpty()) {
            throw new DeviceException(NET_MESSAGE);
        }
        return out.data;
    }

    public record HttpAsk(String url, String dataB64) {
        public static HttpAsk parse(String rest) throws DeviceException {
            String line = rest == null ? "" : rest.trim();
            if(line.startsWith("HTTP POST ")) {
                line = line.substring(10).trim();
            }
            int sp = line.lastIndexOf(' ');
            if(sp < 8) {
                throw new DeviceException("Unexpected Banshee oracle request: " + rest);
            }
            return new HttpAsk(line.substring(0, sp).trim(), line.substring(sp + 1).trim());
        }
    }

    static String jsonString(String raw, String key) {
        try {
            return JSON.readTree(raw == null ? "{}" : raw).path(key).asText("");
        } catch(Exception e) {
            return "";
        }
    }

    static Result handle(String kind, String dataB64) {
        KeyFile key;
        Parsed parsed;
        try {
            Decoded decoded = decodeWithAnyKey(dataB64);
            key = decoded.key;
            parsed = decoded.parsed;
        } catch(Exception e) {
            return Result.net();
        }
        try {
            String pinHash = Utils.bytesToHex(sha256(parsed.pinSecret));
            Path recFile = pinFile(parsed.deviceId);
            PinRec rec = readPin(recFile);
            if("set_pin".equals(kind)) {
                if(rec != null && parsed.replay == rec.replay) {
                    return Result.net();
                }
                byte[] share = takeShare(key.priv, pinHash);
                rec = new PinRec(pinHash, wrapShare(key.priv, parsed.deviceId, share), 0, parsed.replay);
                writePin(recFile, rec);
                writePin(pinFile(pinHash), new PinRec(pinHash, wrapShare(key.priv, pinHash, share), 0, parsed.replay));
                return Result.ok(encodeReply(parsed.respKey, 0, share, 0));
            }
            ShareFound found = resolveShare(key.priv, parsed.deviceId, pinHash, rec);
            if(found == null) {
                return Result.ok(encodeReply(parsed.respKey, 1, null, 1));
            }
            if(!found.fromRestore() && parsed.replay <= found.replay()) {
                return Result.net();
            }
            if(found.matched()) {
                PinRec okRec = new PinRec(pinHash, wrapShare(key.priv, parsed.deviceId, found.share()), 0, parsed.replay);
                writePin(recFile, okRec);
                writePin(pinFile(pinHash), new PinRec(pinHash, wrapShare(key.priv, pinHash, found.share()), 0, parsed.replay));
                return Result.ok(encodeReply(parsed.respKey, 0, found.share(), 0));
            }
            int fails = found.fails() + 1;
            if(fails >= MAX_FAILS) {
                Files.deleteIfExists(recFile);
                return Result.ok(encodeReply(parsed.respKey, 2, null, MAX_FAILS));
            }
            writePin(recFile, new PinRec(found.pinHash(), found.wrapped(), fails, parsed.replay));
            return Result.ok(encodeReply(parsed.respKey, 1, null, fails));
        } catch(Exception e) {
            return Result.net();
        }
    }

    private static Decoded decodeWithAnyKey(String dataB64) throws Exception {
        List<KeyFile> keys = loadAllKeys();
        Exception last = null;
        for(KeyFile key : keys) {
            try {
                return new Decoded(key, decodeRequest(key, dataB64));
            } catch(Exception e) {
                last = e;
            }
        }
        if(last != null) {
            throw last;
        }
        throw new IllegalArgumentException("no_oracle_key");
    }

    private static List<KeyFile> loadAllKeys() throws DeviceException, IOException {
        List<KeyFile> keys = new ArrayList<>();
        KeyFile primary = loadKey();
        keys.add(primary);
        Path extraDir = root().resolve("keys");
        if(Files.isDirectory(extraDir)) {
            try(java.util.stream.Stream<Path> files = Files.list(extraDir)) {
                for(Path file : files.filter(p -> p.getFileName().toString().endsWith(".json")).toList()) {
                    KeyFile extra = readKeyFile(file);
                    if(extra != null && extra.priv() != null && extra.pub() != null && !eqPub(primary.pub(), extra.pub())) {
                        keys.add(extra);
                    }
                }
            }
        }
        return keys;
    }

    private static Parsed decodeRequest(KeyFile studio, String dataB64) throws Exception {
        byte[] wire = Base64.getDecoder().decode(dataB64 == null ? "" : dataB64);
        if(wire.length != WIRE_LEN) {
            throw new IllegalArgumentException("bad_wire");
        }
        byte[] cke = Arrays.copyOfRange(wire, 0, CKE_LEN);
        byte[] counter = Arrays.copyOfRange(wire, CKE_LEN, CKE_LEN + CTR_LEN);
        byte[] enc = Arrays.copyOfRange(wire, CKE_LEN + CTR_LEN, wire.length);
        byte[] shared = ecdhX(Utils.hexToBytes(studio.priv), cke);
        byte[] reqKey = hmac(shared, concat(LABEL_REQ, counter));
        byte[] respKey = hmac(shared, concat(LABEL_RESP, counter));
        byte[] plain = gcmDecrypt(reqKey, enc, PLAIN_LEN);
        byte[] pinSecret = Arrays.copyOfRange(plain, 0, PIN_LEN);
        byte[] entropy = Arrays.copyOfRange(plain, PIN_LEN, PIN_LEN + ENT_LEN);
        byte[] unitPub = Arrays.copyOfRange(plain, PIN_LEN + ENT_LEN, PIN_LEN + ENT_LEN + PUB_LEN);
        byte[] sig = Arrays.copyOfRange(plain, PIN_LEN + ENT_LEN + PUB_LEN, PLAIN_LEN);
        byte[] transcript = concat(cke, counter, pinSecret, entropy);
        if(!verifyP1363(unitPub, transcript, sig)) {
            throw new IllegalArgumentException("bad_sig");
        }
        long replay = ByteBuffer.wrap(counter).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xffffffffL;
        String deviceId = Utils.bytesToHex(sha256(unitPub));
        return new Parsed(reqKey, respKey, pinSecret, replay, deviceId);
    }

    private static String encodeReply(byte[] respKey, int status, byte[] share, int fails) throws GeneralSecurityException {
        byte[] plain = new byte[RESP_PLAIN_LEN];
        plain[0] = (byte)status;
        if(share != null) {
            System.arraycopy(share, 0, plain, 1, 32);
        }
        plain[RESP_PLAIN_LEN - 1] = (byte)fails;
        return Base64.getEncoder().encodeToString(gcmEncrypt(respKey, plain));
    }

    private static boolean verifyP1363(byte[] pub33, byte[] transcript, byte[] sig64) {
        if(sig64 == null || sig64.length != SIG_LEN) {
            return false;
        }
        byte[] hash = sha256(transcript);
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig64, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig64, 32, 64));
        return new ECDSASignature(r, s).verify(hash, pub33);
    }

    static byte[] ecdhX(byte[] priv32, byte[] pub33) {
        ECKey remote = ECKey.fromPublicOnly(pub33);
        ECKey local = ECKey.fromPrivate(priv32, true);
        byte[] compressed = remote.multiply(local.getPrivKey(), true).getPubKey();
        return Arrays.copyOfRange(compressed, 1, 33);
    }

    static byte[] hmac(byte[] key, byte[] msg) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(msg);
    }

    static byte[] sha256(byte[] in) {
        return Sha256Hash.hash(in);
    }

    static byte[] gcmEncrypt(byte[] key, byte[] plain) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LEN];
        RNG.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, iv));
        byte[] ctAndTag = cipher.doFinal(plain);
        return concat(iv, ctAndTag);
    }

    static byte[] gcmDecrypt(byte[] key, byte[] wire, int plainLen) throws GeneralSecurityException {
        if(wire.length != IV_LEN + plainLen + TAG_LEN) {
            throw new IllegalArgumentException("bad_len");
        }
        byte[] iv = Arrays.copyOfRange(wire, 0, IV_LEN);
        byte[] ctAndTag = Arrays.copyOfRange(wire, IV_LEN, wire.length);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LEN * 8, iv));
        return cipher.doFinal(ctAndTag);
    }

    private static String wrapShare(String privHex, String deviceId, byte[] share) throws GeneralSecurityException {
        byte[] key = hmac(Utils.hexToBytes(privHex), concat(LABEL_STORE, Utils.hexToBytes(deviceId)));
        return Base64.getEncoder().encodeToString(gcmEncrypt(key, share));
    }

    private static byte[] unwrapShare(String privHex, String deviceId, String b64) throws GeneralSecurityException {
        byte[] key = hmac(Utils.hexToBytes(privHex), concat(LABEL_STORE, Utils.hexToBytes(deviceId)));
        return gcmDecrypt(key, Base64.getDecoder().decode(b64), 32);
    }

    private static synchronized KeyFile loadKey() throws DeviceException {
        try {
            Path dir = root();
            BansheeSecureFiles.ownerOnlyDir(dir);
            Path file = keyFile();
            if(Files.exists(file)) {
                KeyFile loaded = readKeyFile(file);
                BansheeSecureFiles.ownerOnly(file);
                return loaded;
            }
            ECKey key = new ECKey();
            KeyFile created = new KeyFile(
                    Utils.bytesToHex(Utils.bigIntegerToBytes(key.getPrivKey(), 32)),
                    Utils.bytesToHex(key.getPubKey()));
            writeKeyFile(file, created);
            return created;
        } catch(IOException e) {
            throw new DeviceException("Could not load Light oracle key", e);
        }
    }

    public static synchronized Snapshot snapshot() throws DeviceException {
        try {
            KeyFile key = readKeyFile(keyFile());
            List<PinEntry> pins = new ArrayList<>();
            Path dir = root().resolve("pins");
            if(Files.isDirectory(dir)) {
                try(java.util.stream.Stream<Path> files = Files.list(dir)) {
                    for(Path file : files.filter(p -> p.getFileName().toString().endsWith(".json")).toList()) {
                        String name = file.getFileName().toString();
                        String deviceId = name.substring(0, name.length() - 5).toLowerCase(Locale.ROOT);
                        if(!DEVICE_ID.matcher(deviceId).matches()) {
                            continue;
                        }
                        PinRec rec = readPin(file);
                        if(rec != null) {
                            pins.add(new PinEntry(deviceId, rec.pinHash, rec.share, rec.fails, rec.replay));
                        }
                    }
                }
            }
            byte[] exported = shareFromPins(key, pins);
            if(exported == null && key != null && key.priv() != null) {
                exported = loadPendingShare(key.priv());
            }
            return new Snapshot(key, List.copyOf(pins), exported == null ? null : Utils.bytesToHex(exported));
        } catch(IOException e) {
            throw new DeviceException("Could not read Light oracle config", e);
        }
    }

    public static synchronized AppendResult appendSnapshot(Snapshot snapshot) throws DeviceException {
        return appendSnapshot(snapshot, false);
    }

    public static synchronized AppendResult appendSnapshot(Snapshot snapshot, boolean replacePins) throws DeviceException {
        if(snapshot == null) {
            return new AppendResult(false, false, 0, 0, 0);
        }
        try {
            Path dir = root();
            BansheeSecureFiles.ownerOnlyDir(dir);
            boolean wrotePrimary = false;
            boolean wroteExtra = false;
            KeyFile incoming = snapshot.key();
            if(incoming != null && incoming.priv() != null && incoming.pub() != null) {
                Path primaryFile = keyFile();
                KeyFile primary = readKeyFile(primaryFile);
                if(primary == null) {
                    writeKeyFile(primaryFile, incoming);
                    wrotePrimary = true;
                } else if(!eqPub(primary.pub(), incoming.pub())) {
                    String pub = incoming.pub().trim().toLowerCase(Locale.ROOT);
                    if(PUB_HEX.matcher(pub).matches()) {
                        Path extraDir = dir.resolve("keys");
                        BansheeSecureFiles.ownerOnlyDir(extraDir);
                        Path extraFile = extraDir.resolve(pub + ".json");
                        if(!Files.exists(extraFile)) {
                            writeKeyFile(extraFile, incoming);
                            wroteExtra = true;
                        }
                    }
                }
            }
            int added = 0;
            int skipped = 0;
            int replaced = 0;
            if(snapshot.pins() != null) {
                for(PinEntry pin : snapshot.pins()) {
                    if(pin == null || pin.deviceId() == null) {
                        continue;
                    }
                    String deviceId = pin.deviceId().trim().toLowerCase(Locale.ROOT);
                    if(!DEVICE_ID.matcher(deviceId).matches()) {
                        continue;
                    }
                    Path recFile = pinFile(deviceId);
                    if(Files.exists(recFile) && !replacePins) {
                        skipped++;
                        continue;
                    }
                    boolean existed = Files.exists(recFile);
                    writePin(recFile, new PinRec(pin.pinHash(), pin.share(), pin.fails(), pin.replay()));
                    if(existed) {
                        replaced++;
                    } else {
                        added++;
                    }
                }
            }
            return new AppendResult(wrotePrimary, wroteExtra, added, skipped, replaced);
        } catch(IOException e) {
            throw new DeviceException("Could not append Light oracle config", e);
        }
    }

    public static byte[] pinSecret(String oraclePubHex, String sequence) {
        try {
            return hmac(Utils.hexToBytes(oraclePubHex), sequence.getBytes(StandardCharsets.US_ASCII));
        } catch(GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String pinHash(String oraclePubHex, String sequence) {
        return Utils.bytesToHex(sha256(pinSecret(oraclePubHex, sequence)));
    }

    public static byte[] exportShare(Snapshot snapshot) {
        if(snapshot == null || snapshot.key() == null) {
            return null;
        }
        String hex = snapshot.wrapShareHex();
        if(hex != null && hex.length() == 64 && hex.matches("[0-9a-fA-F]+")) {
            return Utils.hexToBytes(hex);
        }
        return shareFromPins(snapshot.key(), snapshot.pins());
    }

    public static synchronized void enrollWallet(KeyFile key, byte[] share) throws DeviceException {
        if(key == null || key.priv() == null || key.pub() == null || share == null || share.length != 32) {
            throw new DeviceException("Backup is missing Light oracle share");
        }
        try {
            promoteKey(key);
        } catch(IOException e) {
            throw new DeviceException("Could not enroll Light oracle key", e);
        }
        restoreShare = Arrays.copyOf(share, 32);
        try {
            writePin(pendingShareFile(), new PinRec(PENDING_WRAP_ID, wrapShare(key.priv(), PENDING_WRAP_ID, restoreShare), 0, 0));
        } catch(Exception e) {
            throw new DeviceException("Could not enroll Light oracle share", e);
        }
    }

    private static void promoteKey(KeyFile incoming) throws IOException, DeviceException {
        Path dir = root();
        BansheeSecureFiles.ownerOnlyDir(dir);
        Path primaryFile = keyFile();
        KeyFile primary = readKeyFile(primaryFile);
        if(primary != null && !eqPub(primary.pub(), incoming.pub())) {
            String pub = primary.pub().trim().toLowerCase(Locale.ROOT);
            if(PUB_HEX.matcher(pub).matches()) {
                Path extraDir = dir.resolve("keys");
                BansheeSecureFiles.ownerOnlyDir(extraDir);
                Path extraFile = extraDir.resolve(pub + ".json");
                if(!Files.exists(extraFile)) {
                    writeKeyFile(extraFile, primary);
                }
            }
        }
        writeKeyFile(primaryFile, incoming);
    }

    private static byte[] shareFromPins(KeyFile key, List<PinEntry> pins) {
        if(key == null || key.priv() == null || pins == null) {
            return null;
        }
        for(PinEntry pin : pins) {
            if(pin == null || pin.deviceId() == null || pin.share() == null) {
                continue;
            }
            try {
                return unwrapShare(key.priv(), pin.deviceId(), pin.share());
            } catch(Exception ignored) {
            }
        }
        return null;
    }

    private static byte[] takeShare(String privHex, String pinHash) throws Exception {
        byte[] pending = loadPendingShare(privHex);
        if(pending != null) {
            return pending;
        }
        PinRec canon = readPin(pinFile(pinHash));
        if(canon != null) {
            return unwrapShare(privHex, pinHash, canon.share);
        }
        byte[] share = new byte[32];
        RNG.nextBytes(share);
        return share;
    }

    private static ShareFound resolveShare(String privHex, String deviceId, String pinHash, PinRec rec) throws Exception {
        byte[] pending = loadPendingShare(privHex);
        if(pending != null) {
            return new ShareFound(pending, true, 0, 0, pinHash, null, true);
        }
        if(rec != null && MessageDigest.isEqual(Utils.hexToBytes(rec.pinHash), Utils.hexToBytes(pinHash))) {
            return new ShareFound(unwrapShare(privHex, deviceId, rec.share), true, rec.fails, rec.replay, rec.pinHash, rec.share, false);
        }
        PinRec canon = readPin(pinFile(pinHash));
        if(canon != null && MessageDigest.isEqual(Utils.hexToBytes(canon.pinHash), Utils.hexToBytes(pinHash))) {
            long replay = rec == null ? 0 : rec.replay;
            return new ShareFound(unwrapShare(privHex, pinHash, canon.share), true, 0, replay, pinHash, canon.share, false);
        }
        if(rec != null) {
            return new ShareFound(null, false, rec.fails, rec.replay, rec.pinHash, rec.share, false);
        }
        return null;
    }

    private static byte[] loadPendingShare(String privHex) {
        if(restoreShare != null) {
            return Arrays.copyOf(restoreShare, 32);
        }
        try {
            PinRec pending = readPin(pendingShareFile());
            if(pending == null || pending.share == null) {
                return null;
            }
            byte[] share = unwrapShare(privHex, PENDING_WRAP_ID, pending.share);
            restoreShare = Arrays.copyOf(share, 32);
            return share;
        } catch(Exception e) {
            return null;
        }
    }

    public static boolean hasLocalShare() {
        try {
            if(restoreShare != null) {
                return true;
            }
            if(Files.exists(pendingShareFile())) {
                return true;
            }
            Path dir = root().resolve("pins");
            if(!Files.isDirectory(dir)) {
                return false;
            }
            try(java.util.stream.Stream<Path> files = Files.list(dir)) {
                return files.anyMatch(p -> p.getFileName().toString().endsWith(".json"));
            }
        } catch(IOException e) {
            return false;
        }
    }

    private static Path keyFile() {
        return root().resolve("oracle-key.json");
    }

    private static Path pendingShareFile() {
        return root().resolve("pending-share.json");
    }

    private static KeyFile readKeyFile(Path file) throws IOException {
        if(file == null || !Files.exists(file)) {
            return null;
        }
        return JSON.readValue(file.toFile(), KeyFile.class);
    }

    private static void writeKeyFile(Path file, KeyFile key) throws IOException {
        Path tmp = Path.of(file.toString() + ".tmp");
        JSON.writerWithDefaultPrettyPrinter().writeValue(tmp.toFile(), key);
        try {
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch(IOException e) {
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        BansheeSecureFiles.ownerOnly(file);
    }

    private static boolean eqPub(String a, String b) {
        if(a == null || b == null) {
            return false;
        }
        return a.trim().equalsIgnoreCase(b.trim());
    }

    private static Path pinFile(String deviceId) throws IOException {
        Path dir = root().resolve("pins");
        BansheeSecureFiles.ownerOnlyDir(dir);
        return dir.resolve(deviceId + ".json");
    }

    private static PinRec readPin(Path file) throws IOException {
        if(!Files.exists(file)) {
            return null;
        }
        return JSON.readValue(file.toFile(), PinRec.class);
    }

    private static void writePin(Path file, PinRec rec) throws IOException {
        Path tmp = Path.of(file.toString() + ".tmp");
        JSON.writeValue(tmp.toFile(), rec);
        try {
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                    java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch(IOException e) {
            Files.move(tmp, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
        BansheeSecureFiles.ownerOnly(file);
    }

    private static Path root() {
        if(root == null) {
            root = Path.of(System.getProperty("user.home"), "AppData", "Roaming", "Banshee Light", "oracle");
        }
        return root;
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for(byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int i = 0;
        for(byte[] p : parts) {
            System.arraycopy(p, 0, out, i, p.length);
            i += p.length;
        }
        return out;
    }

    record Result(String data) {
        static Result ok(String data) {
            return new Result(data);
        }

        static Result net() {
            return new Result(null);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record KeyFile(String priv, String pub) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record PinRec(String pinHash, String share, int fails, long replay) {
    }

    public record PinEntry(String deviceId, String pinHash, String share, int fails, long replay) {
    }

    public record Snapshot(KeyFile key, List<PinEntry> pins, String wrapShareHex) {
        public Snapshot(KeyFile key, List<PinEntry> pins) {
            this(key, pins, null);
        }

        public boolean present() {
            return key != null || (pins != null && !pins.isEmpty()) || (wrapShareHex != null && !wrapShareHex.isBlank());
        }
    }

    public record AppendResult(boolean wrotePrimaryKey, boolean wroteExtraKey, int pinsAdded, int pinsSkipped, int pinsReplaced) {
    }

    private record ShareFound(byte[] share, boolean matched, int fails, long replay, String pinHash, String wrapped,
                              boolean fromRestore) {
    }

    private record Parsed(byte[] reqKey, byte[] respKey, byte[] pinSecret, long replay, String deviceId) {
    }

    private record Decoded(KeyFile key, Parsed parsed) {
    }
}
