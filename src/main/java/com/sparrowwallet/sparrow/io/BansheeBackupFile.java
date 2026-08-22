// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.sparrow.io;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sparrowwallet.lark.BansheeOracle;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** SHA-256-sealed clone + oracle (v7). v6 PBKDF2 words, v5 PEM+sequence, v4 PEM, and v3 passphrase still open. */
public final class BansheeBackupFile {
    public static final String FORMAT = "banshee-backup";
    public static final int VERSION = 7;
    public static final int PBKDF2_WORDS_VERSION = 6;
    public static final int SEQUENCE_VERSION = 5;
    public static final int PEM_VERSION = 4;
    public static final int PASSPHRASE_VERSION = 3;
    public static final int RECOVERY_WORD_COUNT = 12;
    private static final int ITERATIONS = 200_000;
    private static final int SEQ_MIN = 6;
    private static final int SEQ_MAX = 12;
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();
    private static final Gson COMPACT = new Gson();

    private BansheeBackupFile() {
    }

    public static int peekVersion(String json) {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        if(!FORMAT.equals(obj.get("format").getAsString())) {
            throw new IllegalArgumentException("Not a Banshee backup file");
        }
        return obj.get("version").getAsInt();
    }

    public static String normalizeSequence(char[] sequence) {
        if(sequence == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(sequence.length);
        for(char c : sequence) {
            char u = Character.toUpperCase(c);
            if(u == 'L' || u == 'R') {
                sb.append(u);
            }
        }
        return sb.toString();
    }

    public static void checkSequence(String sequence) {
        if(sequence == null || sequence.length() < SEQ_MIN || sequence.length() > SEQ_MAX) {
            throw new IllegalArgumentException("Unlock sequence must be " + SEQ_MIN + "–" + SEQ_MAX + " L/R presses.");
        }
        boolean hasL = false;
        boolean hasR = false;
        for(int i = 0; i < sequence.length(); i++) {
            char c = sequence.charAt(i);
            if(c == 'L') {
                hasL = true;
            } else if(c == 'R') {
                hasR = true;
            } else {
                throw new IllegalArgumentException("Unlock sequence can only contain L and R.");
            }
        }
        if(!hasL || !hasR) {
            throw new IllegalArgumentException("Unlock sequence must include both Left and Right.");
        }
    }

    public static String normalizeRecoveryWords(char[] words) {
        if(words == null || words.length == 0) {
            return "";
        }
        StringBuilder digits = new StringBuilder();
        for(char c : words) {
            if(c >= '1' && c <= '6') {
                digits.append(c);
            }
        }
        if(digits.length() == RECOVERY_WORD_COUNT * 5) {
            StringBuilder codes = new StringBuilder(RECOVERY_WORD_COUNT * 6);
            for(int i = 0; i < RECOVERY_WORD_COUNT; i++) {
                if(i > 0) {
                    codes.append(' ');
                }
                codes.append(digits, i * 5, i * 5 + 5);
            }
            return codes.toString();
        }
        StringBuilder sb = new StringBuilder();
        for(char c : words) {
            if(Character.isWhitespace(c)) {
                if(sb.length() > 0 && sb.charAt(sb.length() - 1) != ' ') {
                    sb.append(' ');
                }
            } else {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString().trim();
    }

    public static void checkRecoveryWords(String words) {
        if(words == null || words.isBlank()) {
            throw new IllegalArgumentException("Enter the " + RECOVERY_WORD_COUNT
                    + " five-digit dice rolls shown on the device after the roll.");
        }
        String[] parts = words.split(" ");
        if(parts.length != RECOVERY_WORD_COUNT) {
            throw new IllegalArgumentException("Backup restore uses exactly " + RECOVERY_WORD_COUNT
                    + " dice rolls (got " + parts.length + ").");
        }
        boolean dice = parts[0].matches("[1-6]{5}");
        for(String part : parts) {
            if(dice) {
                if(!part.matches("[1-6]{5}")) {
                    throw new IllegalArgumentException("Each roll is five dice (digits 1–6), like 36421.");
                }
            } else if(part.length() < 2 || part.length() > 20 || !part.matches("[a-z]+")) {
                throw new IllegalArgumentException("Type the 12 five-digit rolls from the device (or older 12 words).");
            }
        }
    }

    public static byte[] wrapKeyFromWords(String words) throws Exception {
        String normalized = words == null ? "" : words;
        checkRecoveryWords(normalized);
        return MessageDigest.getInstance("SHA-256").digest(normalized.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] wrapKeyFromHex(String hex) {
        if(hex == null) {
            throw new IllegalArgumentException("Backup wrap key missing.");
        }
        String h = hex.trim();
        if(h.length() != 64 || !h.matches("[0-9a-fA-F]{64}")) {
            throw new IllegalArgumentException("Backup wrap key must be 64 hex characters.");
        }
        byte[] out = new byte[32];
        for(int i = 0; i < 32; i++) {
            out[i] = (byte)Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    public static String wrapKeyHex(byte[] key) {
        if(key == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(key.length * 2);
        for(byte b : key) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    public static String seal(String fingerprint, String clone, BansheeOracle.Snapshot oracle, char[] recoveryWords) throws Exception {
        String words = normalizeRecoveryWords(recoveryWords);
        return seal(fingerprint, clone, oracle, wrapKeyFromWords(words));
    }

    public static String seal(String fingerprint, String clone, BansheeOracle.Snapshot oracle, byte[] wrapKey) throws Exception {
        if(wrapKey == null || wrapKey.length != 32) {
            throw new IllegalArgumentException("Backup wrap key must be 32 bytes.");
        }
        JsonObject inner = new JsonObject();
        inner.addProperty("clone", clone);
        inner.add("oracle", oracleJson(oracle));
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(wrapKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(COMPACT.toJson(inner).getBytes(StandardCharsets.UTF_8));
        JsonObject obj = new JsonObject();
        obj.addProperty("format", FORMAT);
        obj.addProperty("version", VERSION);
        obj.addProperty("fingerprint", fingerprint.toLowerCase());
        obj.addProperty("exportedAt", java.time.Instant.now().toString());
        obj.addProperty("kdf", "sha256");
        obj.addProperty("alg", "aes-256-gcm");
        obj.addProperty("iv", b64(iv));
        obj.addProperty("ciphertext", b64(ct));
        return GSON.toJson(obj) + "\n";
    }

    public static String seal(String fingerprint, String clone, BansheeOracle.Snapshot oracle, String pem) throws Exception {
        return seal(fingerprint, clone, oracle, pem, null);
    }

    public static String seal(String fingerprint, String clone, BansheeOracle.Snapshot oracle, String pem, char[] sequence) throws Exception {
        JsonObject inner = new JsonObject();
        inner.addProperty("clone", clone);
        inner.add("oracle", oracleJson(oracle));
        String innerJson = COMPACT.toJson(inner);
        int version = SEQUENCE_VERSION;
        byte[] toWrap;
        if(sequence != null && sequence.length > 0) {
            String seq = normalizeSequence(sequence);
            checkSequence(seq);
            toWrap = sealWithSequence(innerJson, seq).getBytes(StandardCharsets.UTF_8);
        } else {
            version = PEM_VERSION;
            toWrap = innerJson.getBytes(StandardCharsets.UTF_8);
        }
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        PemWrap wrap = wrapPem(pem);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrap.key, new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(toWrap);
        String fp = fingerprint.toLowerCase();
        String ivB64 = b64(iv);
        String ctB64 = b64(ct);
        byte[] signature = EspSecureBootV2.pssSign(wrap.rsa, transcript(fp, wrap.keyId, ivB64, ctB64));
        JsonObject obj = new JsonObject();
        obj.addProperty("format", FORMAT);
        obj.addProperty("version", version);
        obj.addProperty("fingerprint", fp);
        obj.addProperty("exportedAt", java.time.Instant.now().toString());
        obj.addProperty("keyId", wrap.keyId);
        obj.addProperty("alg", "aes-256-gcm");
        obj.addProperty("iv", ivB64);
        obj.addProperty("ciphertext", ctB64);
        obj.addProperty("signature", b64(signature));
        return GSON.toJson(obj) + "\n";
    }

    /** Legacy passphrase wrap (v3). */
    public static String seal(String fingerprint, String payload, char[] passphrase) throws Exception {
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);
        byte[] key = derive(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));
        JsonObject obj = new JsonObject();
        obj.addProperty("format", FORMAT);
        obj.addProperty("version", PASSPHRASE_VERSION);
        obj.addProperty("fingerprint", fingerprint.toLowerCase());
        obj.addProperty("exportedAt", java.time.Instant.now().toString());
        obj.addProperty("kdf", "pbkdf2-sha256");
        obj.addProperty("iterations", ITERATIONS);
        obj.addProperty("salt", b64(salt));
        obj.addProperty("alg", "aes-256-gcm");
        obj.addProperty("iv", b64(iv));
        obj.addProperty("ciphertext", b64(ct));
        return GSON.toJson(obj) + "\n";
    }

    public static Opened openPem(String json, String pem) throws Exception {
        return openPem(json, pem, null);
    }

    public static Opened openPem(String json, String pem, char[] sequence) throws Exception {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        if(!FORMAT.equals(obj.get("format").getAsString())) {
            throw new IllegalArgumentException("Not a Banshee backup file");
        }
        int version = obj.get("version").getAsInt();
        if(version == PASSPHRASE_VERSION) {
            throw new IllegalArgumentException("This backup uses a passphrase. Enter the passphrase, not a .pem.");
        }
        if(version == VERSION || version == PBKDF2_WORDS_VERSION) {
            throw new IllegalArgumentException("This backup is sealed with the 12 recovery words shown on the device, not a .pem.");
        }
        if(version != SEQUENCE_VERSION && version != PEM_VERSION) {
            throw new IllegalArgumentException("Studio PEM backups cannot be opened here. Create a new backup in Banshee Light.");
        }
        if(version == SEQUENCE_VERSION && (sequence == null || sequence.length == 0)) {
            throw new IllegalArgumentException("This backup is sealed with the original unlock sequence. Enter that L/R sequence.");
        }
        String fingerprint = obj.get("fingerprint").getAsString().trim().toLowerCase();
        String keyId = obj.get("keyId").getAsString().trim().toLowerCase();
        String ivB64 = obj.get("iv").getAsString().trim();
        String ctB64 = obj.get("ciphertext").getAsString().trim();
        String sigB64 = obj.has("signature") ? obj.get("signature").getAsString().trim() : "";
        if(keyId.isEmpty() || ivB64.isEmpty() || ctB64.isEmpty() || sigB64.isEmpty()) {
            throw new IllegalArgumentException("Backup file is missing signing-key encryption");
        }
        PemWrap wrap = wrapPem(pem);
        if(!keyId.equals(wrap.keyId)) {
            throw new IllegalArgumentException("Wrong signing key for this backup. Choose the same .pem used when the backup was created.");
        }
        if(!EspSecureBootV2.pssVerify(wrap.rsa, transcript(fingerprint, keyId, ivB64, ctB64), unb64(sigB64))) {
            throw new IllegalArgumentException("Wrong signing key for this backup. Choose the same .pem used when the backup was created.");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, wrap.key, new GCMParameterSpec(128, unb64(ivB64)));
        String innerJson = new String(cipher.doFinal(unb64(ctB64)), StandardCharsets.UTF_8);
        if(version == SEQUENCE_VERSION) {
            innerJson = openWithSequence(innerJson, sequence);
        }
        JsonObject inner = JsonParser.parseString(innerJson).getAsJsonObject();
        if(!inner.has("clone")) {
            throw new IllegalArgumentException("This backup has no Light oracle config. Create a new backup in Banshee Light.");
        }
        String clone = inner.get("clone").getAsString();
        return new Opened(fingerprint, clone, parseOracle(inner.get("oracle")));
    }

    public static Opened open(String json, char[] passphrase) throws Exception {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        if(!FORMAT.equals(obj.get("format").getAsString())) {
            throw new IllegalArgumentException("Not a Banshee backup file");
        }
        int version = obj.get("version").getAsInt();
        if(version == VERSION || version == PBKDF2_WORDS_VERSION) {
            throw new IllegalArgumentException("This backup is sealed with the 12 recovery words shown on the device after the dice roll.");
        }
        if(version == SEQUENCE_VERSION || version == PEM_VERSION) {
            throw new IllegalArgumentException("This Light backup needs the .pem signing key, not a passphrase.");
        }
        if(version != PASSPHRASE_VERSION) {
            throw new IllegalArgumentException("This Light backup is version 3 (passphrase). Studio PEM backups cannot be opened here.");
        }
        String fingerprint = obj.get("fingerprint").getAsString().trim().toLowerCase();
        byte[] salt = unb64(obj.get("salt").getAsString());
        byte[] iv = unb64(obj.get("iv").getAsString());
        byte[] ct = unb64(obj.get("ciphertext").getAsString());
        byte[] key = derive(passphrase, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        String payload = new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        return new Opened(fingerprint, payload, null);
    }

    public static Opened openWords(String json, char[] recoveryWords) throws Exception {
        JsonObject obj = JsonParser.parseString(json).getAsJsonObject();
        if(!FORMAT.equals(obj.get("format").getAsString())) {
            throw new IllegalArgumentException("Not a Banshee backup file");
        }
        int version = obj.get("version").getAsInt();
        if(version != VERSION && version != PBKDF2_WORDS_VERSION) {
            throw new IllegalArgumentException("This backup is not sealed with recovery words. Use Restore and follow the prompt for this file.");
        }
        String words = normalizeRecoveryWords(recoveryWords);
        checkRecoveryWords(words);
        String fingerprint = obj.get("fingerprint").getAsString().trim().toLowerCase();
        byte[] key;
        if(version == VERSION) {
            key = wrapKeyFromWords(words);
        } else {
            int iterations = obj.has("iterations") ? obj.get("iterations").getAsInt() : ITERATIONS;
            if(iterations != ITERATIONS) {
                throw new IllegalArgumentException("Unsupported backup key derivation");
            }
            key = derive(words.toCharArray(), unb64(obj.get("salt").getAsString()));
        }
        byte[] iv = unb64(obj.get("iv").getAsString());
        byte[] ct = unb64(obj.get("ciphertext").getAsString());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        String innerJson;
        try {
            innerJson = new String(cipher.doFinal(ct), StandardCharsets.UTF_8);
        } catch(Exception e) {
            throw new IllegalArgumentException("Wrong recovery words for this backup.");
        }
        JsonObject inner = JsonParser.parseString(innerJson).getAsJsonObject();
        if(!inner.has("clone")) {
            throw new IllegalArgumentException("This backup has no clone payload. Create a new backup in Banshee Light.");
        }
        return new Opened(fingerprint, inner.get("clone").getAsString(), parseOracle(inner.get("oracle")));
    }

    private static String sealWithSequence(String innerJson, String sequence) throws Exception {
        byte[] salt = new byte[16];
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);
        byte[] key = derive(sequence.toCharArray(), salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        byte[] ct = cipher.doFinal(innerJson.getBytes(StandardCharsets.UTF_8));
        JsonObject layer = new JsonObject();
        layer.addProperty("kdf", "pbkdf2-sha256");
        layer.addProperty("iterations", ITERATIONS);
        layer.addProperty("salt", b64(salt));
        layer.addProperty("iv", b64(iv));
        layer.addProperty("ciphertext", b64(ct));
        return COMPACT.toJson(layer);
    }

    private static String openWithSequence(String layerJson, char[] sequence) throws Exception {
        String seq = normalizeSequence(sequence);
        checkSequence(seq);
        JsonObject layer = JsonParser.parseString(layerJson).getAsJsonObject();
        if(!layer.has("salt") || !layer.has("iv") || !layer.has("ciphertext")) {
            throw new IllegalArgumentException("This backup is missing unlock-sequence encryption.");
        }
        int iterations = layer.has("iterations") ? layer.get("iterations").getAsInt() : ITERATIONS;
        if(iterations != ITERATIONS) {
            throw new IllegalArgumentException("Unsupported backup key derivation");
        }
        byte[] key = derive(seq.toCharArray(), unb64(layer.get("salt").getAsString()));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, unb64(layer.get("iv").getAsString())));
        try {
            return new String(cipher.doFinal(unb64(layer.get("ciphertext").getAsString())), StandardCharsets.UTF_8);
        } catch(Exception e) {
            throw new IllegalArgumentException("Wrong unlock sequence for this backup.");
        }
    }

    private static JsonObject oracleJson(BansheeOracle.Snapshot oracle) {
        JsonObject oracleObj = new JsonObject();
        if(oracle != null && oracle.key() != null) {
            JsonObject key = new JsonObject();
            key.addProperty("priv", oracle.key().priv());
            key.addProperty("pub", oracle.key().pub());
            oracleObj.add("key", key);
        }
        JsonArray pins = new JsonArray();
        if(oracle != null && oracle.pins() != null) {
            for(BansheeOracle.PinEntry pin : oracle.pins()) {
                JsonObject p = new JsonObject();
                p.addProperty("deviceId", pin.deviceId());
                p.addProperty("pinHash", pin.pinHash());
                p.addProperty("share", pin.share());
                p.addProperty("fails", pin.fails());
                p.addProperty("replay", pin.replay());
                pins.add(p);
            }
        }
        oracleObj.add("pins", pins);
        String wrapShare = oracle != null ? oracle.wrapShareHex() : null;
        if((wrapShare == null || wrapShare.isBlank()) && oracle != null) {
            byte[] exported = BansheeOracle.exportShare(oracle);
            wrapShare = exported == null ? null : bytesToHex(exported);
        }
        if(wrapShare != null && !wrapShare.isBlank()) {
            oracleObj.addProperty("wrapShare", wrapShare);
        }
        return oracleObj;
    }

    private static BansheeOracle.Snapshot parseOracle(JsonElement el) {
        if(el == null || !el.isJsonObject()) {
            return new BansheeOracle.Snapshot(null, List.of());
        }
        JsonObject obj = el.getAsJsonObject();
        BansheeOracle.KeyFile key = null;
        if(obj.has("key") && obj.get("key").isJsonObject()) {
            JsonObject k = obj.getAsJsonObject("key");
            String priv = text(k, "priv");
            String pub = text(k, "pub");
            if(!priv.isEmpty() && !pub.isEmpty()) {
                key = new BansheeOracle.KeyFile(priv, pub);
            }
        }
        List<BansheeOracle.PinEntry> pins = new ArrayList<>();
        if(obj.has("pins") && obj.get("pins").isJsonArray()) {
            for(JsonElement item : obj.getAsJsonArray("pins")) {
                if(!item.isJsonObject()) {
                    continue;
                }
                JsonObject p = item.getAsJsonObject();
                String deviceId = text(p, "deviceId");
                if(deviceId.isEmpty()) {
                    continue;
                }
                pins.add(new BansheeOracle.PinEntry(
                        deviceId,
                        text(p, "pinHash"),
                        text(p, "share"),
                        p.has("fails") ? p.get("fails").getAsInt() : 0,
                        p.has("replay") ? p.get("replay").getAsLong() : 0));
            }
        }
        String wrapShare = text(obj, "wrapShare");
        return new BansheeOracle.Snapshot(key, List.copyOf(pins), wrapShare.isEmpty() ? null : wrapShare);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for(byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }

    private static String text(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString().trim() : "";
    }

    private static PemWrap wrapPem(String pem) throws Exception {
        String normalized = normalizePem(pem);
        RSAPrivateCrtKey rsa = EspSecureBootV2.parsePem(normalized);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(normalized.getBytes(StandardCharsets.UTF_8));
        String keyId = hex16(digest);
        SecretKeySpec aes = new SecretKeySpec(digest, "AES");
        return new PemWrap(rsa, aes, keyId);
    }

    private static String normalizePem(String pem) {
        String text = pem == null ? "" : pem.replace("\r\n", "\n").trim();
        if(!text.contains("BEGIN") || text.length() < 80) {
            throw new IllegalArgumentException("Choose a valid .pem signing key");
        }
        return text + "\n";
    }

    private static byte[] transcript(String fingerprint, String keyId, String iv, String ciphertext) {
        return (fingerprint + keyId + iv + ciphertext).getBytes(StandardCharsets.UTF_8);
    }

    private static String hex16(byte[] digest) {
        StringBuilder sb = new StringBuilder(16);
        for(int i = 0; i < 8; i++) {
            sb.append(String.format("%02x", digest[i] & 0xff));
        }
        return sb.toString();
    }

    private static byte[] derive(char[] passphrase, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(passphrase, salt, ITERATIONS, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }

    private static String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] unb64(String s) {
        return Base64.getDecoder().decode(s);
    }

    public record Opened(String fingerprint, String payload, BansheeOracle.Snapshot oracle) {
    }

    private record PemWrap(RSAPrivateCrtKey rsa, SecretKeySpec key, String keyId) {
    }
}
