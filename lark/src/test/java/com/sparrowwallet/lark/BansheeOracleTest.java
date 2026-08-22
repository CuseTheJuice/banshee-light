// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import com.sparrowwallet.drongo.Utils;
import com.sparrowwallet.drongo.crypto.ECDSASignature;
import com.sparrowwallet.drongo.crypto.ECKey;
import com.sparrowwallet.drongo.protocol.Sha256Hash;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class BansheeOracleTest {
    @Test
    void parseHttpAsk() throws DeviceException {
        BansheeOracle.HttpAsk ask = BansheeOracle.HttpAsk.parse(
                "HTTP POST http://127.0.0.1/api/oracle/get_pin abc+def/ghi==");
        assertEquals("http://127.0.0.1/api/oracle/get_pin", ask.url());
        assertEquals("abc+def/ghi==", ask.dataB64());
    }

    @Test
    void jsonStringReadsQuotedField() {
        assertEquals("02ab", BansheeOracle.jsonString("{\"pubkey\":\"02ab\"}", "pubkey"));
        assertEquals("YmFzZTY0", BansheeOracle.jsonString("{ \"data\" : \"YmFzZTY0\" }", "data"));
        assertEquals("", BansheeOracle.jsonString("{\"error\":\"oracle_net\"}", "data"));
    }

    @Test
    void setGetAndWipe(@TempDir Path dir) throws Exception {
        BansheeOracle.useDirectory(dir.toFile());
        String pub = BansheeOracle.pubkey();
        ECKey unit = new ECKey();
        String seq = "LRLRLR";
        String set = buildRequest(pub, unit, seq, true, 1);
        String setReply = BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", set);
        assertFalse(setReply.isBlank());
        DeviceException replaySet = assertThrows(DeviceException.class,
                () -> BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", set));
        assertEquals(BansheeOracle.NET_MESSAGE, replaySet.getMessage());

        String get = buildRequest(pub, unit, seq, false, 2);
        String getReply = BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin", get);
        assertFalse(getReply.isBlank());

        DeviceException replayGet = assertThrows(DeviceException.class,
                () -> BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin", get));
        assertEquals(BansheeOracle.NET_MESSAGE, replayGet.getMessage());

        String wipedSet = buildRequest(pub, unit, seq, true, 1);
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", wipedSet).isBlank());

        BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin", buildRequest(pub, unit, "RRRRRR", false, 3));
        BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin", buildRequest(pub, unit, "LLLLLL", false, 4));
        BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin", buildRequest(pub, unit, "RLRLRL", false, 5));
    }

    @Test
    void appendKeepsExistingPin(@TempDir Path dir) throws Exception {
        BansheeOracle.useDirectory(dir.toFile());
        String pub = BansheeOracle.pubkey();
        ECKey unit = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pub, unit, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snap = BansheeOracle.snapshot();
        assertNotNull(snap.key());
        assertTrue(snap.pins().size() >= 1);
        BansheeOracle.PinEntry original = snap.pins().get(0);
        BansheeOracle.Snapshot other = new BansheeOracle.Snapshot(snap.key(), java.util.List.of(
                new BansheeOracle.PinEntry(original.deviceId(), "aa".repeat(32), original.share(), 9, 99)));
        BansheeOracle.AppendResult result = BansheeOracle.appendSnapshot(other);
        assertEquals(0, result.pinsAdded());
        assertEquals(1, result.pinsSkipped());
        BansheeOracle.Snapshot after = BansheeOracle.snapshot();
        assertEquals(original.pinHash(), after.pins().get(0).pinHash());
        assertEquals(original.fails(), after.pins().get(0).fails());
    }

    @Test
    void appendReplacePinsOverwrites(@TempDir Path dir) throws Exception {
        BansheeOracle.useDirectory(dir.toFile());
        String pub = BansheeOracle.pubkey();
        ECKey unit = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pub, unit, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snap = BansheeOracle.snapshot();
        BansheeOracle.PinEntry original = snap.pins().get(0);
        BansheeOracle.Snapshot other = new BansheeOracle.Snapshot(snap.key(), java.util.List.of(
                new BansheeOracle.PinEntry(original.deviceId(), "aa".repeat(32), original.share(), 9, 99)));
        BansheeOracle.AppendResult result = BansheeOracle.appendSnapshot(other, true);
        assertEquals(0, result.pinsAdded());
        assertEquals(0, result.pinsSkipped());
        assertEquals(1, result.pinsReplaced());
        BansheeOracle.Snapshot after = BansheeOracle.snapshot();
        assertEquals("aa".repeat(32), after.pins().get(0).pinHash());
        assertEquals(9, after.pins().get(0).fails());
        assertEquals(99, after.pins().get(0).replay());
    }

    @Test
    void appendExtraKeyServesBothDevices(@TempDir Path root) throws Exception {
        Path a = root.resolve("a");
        Path b = root.resolve("b");
        java.nio.file.Files.createDirectories(a);
        java.nio.file.Files.createDirectories(b);

        BansheeOracle.useDirectory(a.toFile());
        String pubA = BansheeOracle.pubkey();
        ECKey unitA = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pubA, unitA, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snapA = BansheeOracle.snapshot();

        BansheeOracle.useDirectory(b.toFile());
        String pubB = BansheeOracle.pubkey();
        ECKey unitB = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pubB, unitB, "RLRLRL", true, 1));
        String destKey = java.nio.file.Files.readString(b.resolve("oracle-key.json"));

        BansheeOracle.AppendResult result = BansheeOracle.appendSnapshot(snapA);
        assertTrue(result.wroteExtraKey());
        assertFalse(result.wrotePrimaryKey());
        assertTrue(result.pinsAdded() >= 1);
        assertEquals(destKey, java.nio.file.Files.readString(b.resolve("oracle-key.json")));
        assertTrue(java.nio.file.Files.exists(b.resolve("keys").resolve(snapA.key().pub() + ".json")));

        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pubA, unitA, "LRLRLR", false, 2)).isBlank());
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pubB, unitB, "RLRLRL", false, 2)).isBlank());
    }

    @Test
    void appendPrimaryWhenDestEmpty(@TempDir Path dir) throws Exception {
        BansheeOracle.useDirectory(dir.toFile());
        String pub = BansheeOracle.pubkey();
        ECKey unit = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pub, unit, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snap = BansheeOracle.snapshot();

        Path empty = dir.resolve("empty");
        java.nio.file.Files.createDirectories(empty);
        BansheeOracle.useDirectory(empty.toFile());
        BansheeOracle.AppendResult result = BansheeOracle.appendSnapshot(snap);
        assertTrue(result.wrotePrimaryKey());
        assertFalse(result.wroteExtraKey());
        assertTrue(result.pinsAdded() >= 1);
        assertEquals(pub, BansheeOracle.pubkey());
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pub, unit, "LRLRLR", false, 2)).isBlank());
    }

    @Test
    void enrolledShareServesADifferentUnit(@TempDir Path root) throws Exception {
        Path a = root.resolve("a");
        Path b = root.resolve("b");
        java.nio.file.Files.createDirectories(a);
        java.nio.file.Files.createDirectories(b);

        BansheeOracle.useDirectory(a.toFile());
        String pubA = BansheeOracle.pubkey();
        ECKey unitA = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pubA, unitA, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snapA = BansheeOracle.snapshot();
        byte[] share = BansheeOracle.exportShare(snapA);
        assertNotNull(share);

        BansheeOracle.useDirectory(b.toFile());
        BansheeOracle.enrollWallet(snapA.key(), share);
        ECKey unitB = new ECKey();
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pubA, unitB, "LRLRLR", false, 2)).isBlank());

        BansheeOracle.useDirectory(b.toFile());
        ECKey unitC = new ECKey();
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pubA, unitC, "RLRLRL", false, 2)).isBlank());
    }

    @Test
    void restoredShareIgnoresLeftoverReplay(@TempDir Path root) throws Exception {
        Path a = root.resolve("a");
        Path b = root.resolve("b");
        java.nio.file.Files.createDirectories(a);
        java.nio.file.Files.createDirectories(b);

        BansheeOracle.useDirectory(a.toFile());
        String pubA = BansheeOracle.pubkey();
        ECKey unitA = new ECKey();
        BansheeOracle.post("http://127.0.0.1/api/oracle/set_pin", buildRequest(pubA, unitA, "LRLRLR", true, 1));
        BansheeOracle.Snapshot snapA = BansheeOracle.snapshot();
        byte[] share = BansheeOracle.exportShare(snapA);
        assertNotNull(share);

        BansheeOracle.useDirectory(b.toFile());
        BansheeOracle.pubkey();
        BansheeOracle.appendSnapshot(snapA, true);
        BansheeOracle.enrollWallet(snapA.key(), share);
        String deviceId = Utils.bytesToHex(Sha256Hash.hash(unitA.getPubKey()));
        Path leftover = b.resolve("pins").resolve(deviceId + ".json");
        java.nio.file.Files.createDirectories(leftover.getParent());
        java.nio.file.Files.writeString(leftover,
                "{\"pinHash\":\"" + "ab".repeat(32) + "\",\"share\":\"AAAA\",\"fails\":0,\"replay\":99}");
        assertFalse(BansheeOracle.post("http://127.0.0.1/api/oracle/get_pin",
                buildRequest(pubA, unitA, "LRLRLR", false, 2)).isBlank());
    }

    private static String buildRequest(String oraclePubHex, ECKey unit, String seq, boolean isSet, int counter) throws Exception {
        ECKey cke = new ECKey();
        byte[] ctr = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(counter).array();
        byte[] pin = BansheeOracle.pinSecret(oraclePubHex, seq);
        byte[] entropy = new byte[32];
        if(isSet) {
            new SecureRandom().nextBytes(entropy);
        }
        byte[] ckePub = cke.getPubKey();
        byte[] transcript = concat(ckePub, ctr, pin, entropy);
        ECDSASignature sig = unit.signEcdsa(Sha256Hash.of(transcript));
        byte[] sig64 = concat(Utils.bigIntegerToBytes(sig.r, 32), Utils.bigIntegerToBytes(sig.s, 32));
        byte[] plain = concat(pin, entropy, unit.getPubKey(), sig64);
        byte[] shared = BansheeOracle.ecdhX(Utils.bigIntegerToBytes(cke.getPrivKey(), 32), Utils.hexToBytes(oraclePubHex));
        byte[] reqKey = hmac(shared, concat("banshee_oracle_request".getBytes(StandardCharsets.US_ASCII), ctr));
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(reqKey, "AES"), new GCMParameterSpec(128, iv));
        byte[] ctAndTag = cipher.doFinal(plain);
        byte[] wire = concat(ckePub, ctr, iv, ctAndTag);
        return Base64.getEncoder().encodeToString(wire);
    }

    private static byte[] hmac(byte[] key, byte[] msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(msg);
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
}
