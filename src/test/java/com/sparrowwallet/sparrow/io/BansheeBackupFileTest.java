// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.sparrow.io;

import com.sparrowwallet.lark.BansheeOracle;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class BansheeBackupFileTest {
    private static final String WORDS =
            "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
    private static final String OTHER_WORDS =
            "lima kilo juliet india hotel golf foxtrot echo delta charlie bravo alpha";
    private static final String DICE =
            "11111 11112 11113 11114 11115 11116 11121 11122 11123 11124 11125 11126";

    @Test
    void pemSealOpenRoundTrip() throws Exception {
        String pem = rsaPem();
        BansheeOracle.KeyFile key = new BansheeOracle.KeyFile("ab".repeat(32), "02" + "cd".repeat(32));
        BansheeOracle.PinEntry pin = new BansheeOracle.PinEntry("ef".repeat(32), "11".repeat(32), "c2hhcmU=", 0, 4);
        BansheeOracle.Snapshot oracle = new BansheeOracle.Snapshot(key, List.of(pin));
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmUtcGF5bG9hZA==", oracle, pem, "LRLRLR".toCharArray());
        assertTrue(json.contains("\"version\": 5"));
        assertTrue(json.contains("\"signature\""));
        BansheeBackupFile.Opened opened = BansheeBackupFile.openPem(json, pem, "LRLRLR".toCharArray());
        assertEquals("deadbeef", opened.fingerprint());
        assertEquals("Y2xvbmUtcGF5bG9hZA==", opened.payload());
        assertEquals(key.pub(), opened.oracle().key().pub());
        assertEquals(1, opened.oracle().pins().size());
        assertEquals(pin.deviceId(), opened.oracle().pins().get(0).deviceId());
    }

    @Test
    void wordsSealOpenRoundTrip() throws Exception {
        BansheeOracle.KeyFile key = new BansheeOracle.KeyFile("ab".repeat(32), "02" + "cd".repeat(32));
        BansheeOracle.PinEntry pin = new BansheeOracle.PinEntry("ef".repeat(32), "11".repeat(32), "c2hhcmU=", 0, 4);
        BansheeOracle.Snapshot oracle = new BansheeOracle.Snapshot(key, List.of(pin));
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmUtcGF5bG9hZA==", oracle, WORDS.toCharArray());
        assertTrue(json.contains("\"version\": 7"));
        assertTrue(json.contains("\"kdf\": \"sha256\""));
        assertFalse(json.contains("\"signature\""));
        BansheeBackupFile.Opened opened = BansheeBackupFile.openWords(json, WORDS.toCharArray());
        assertEquals("deadbeef", opened.fingerprint());
        assertEquals("Y2xvbmUtcGF5bG9hZA==", opened.payload());
        assertEquals(key.pub(), opened.oracle().key().pub());
    }

    @Test
    void diceSealOpenRoundTrip() throws Exception {
        BansheeOracle.KeyFile key = new BansheeOracle.KeyFile("ab".repeat(32), "02" + "cd".repeat(32));
        BansheeOracle.PinEntry pin = new BansheeOracle.PinEntry("ef".repeat(32), "11".repeat(32), "c2hhcmU=", 0, 4);
        BansheeOracle.Snapshot oracle = new BansheeOracle.Snapshot(key, List.of(pin));
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmUtcGF5bG9hZA==", oracle, DICE.toCharArray());
        String glued = DICE.replace(" ", "");
        BansheeBackupFile.Opened opened = BansheeBackupFile.openWords(json, glued.toCharArray());
        assertEquals("deadbeef", opened.fingerprint());
        assertEquals("Y2xvbmUtcGF5bG9hZA==", opened.payload());
        assertThrows(IllegalArgumentException.class, () -> BansheeBackupFile.openWords(json, WORDS.toCharArray()));
    }

    @Test
    void wrapKeySealsSameAsWords() throws Exception {
        byte[] key = BansheeBackupFile.wrapKeyFromWords(WORDS);
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), key);
        BansheeBackupFile.Opened opened = BansheeBackupFile.openWords(json, WORDS.toCharArray());
        assertEquals("deadbeef", opened.fingerprint());
        assertEquals("Y2xvbmU=", opened.payload());
        assertEquals(BansheeBackupFile.wrapKeyHex(key),
                BansheeBackupFile.wrapKeyHex(BansheeBackupFile.wrapKeyFromHex(BansheeBackupFile.wrapKeyHex(key))));
    }
    void wrongWordsRejected() throws Exception {
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), WORDS.toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.openWords(json, OTHER_WORDS.toCharArray()));
        assertTrue(err.getMessage().contains("Wrong recovery words"));
    }

    @Test
    void wordsBackupRejectedByPemOpen() throws Exception {
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), WORDS.toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.openPem(json, rsaPem()));
        assertTrue(err.getMessage().contains("recovery words"));
    }

    @Test
    void passphraseOpenRejectsWordsBackup() throws Exception {
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), WORDS.toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.open(json, "secret".toCharArray()));
        assertTrue(err.getMessage().contains("recovery words"));
    }

    @Test
    void generatedPemSealsBackup() throws Exception {
        String pem = EspSecureBootV2.generateSigningKeyPem();
        assertTrue(pem.contains("BEGIN RSA PRIVATE KEY"));
        assertEquals(3072, EspSecureBootV2.parsePem(pem).getModulus().bitLength());
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), pem, "RLRLRL".toCharArray());
        assertEquals("deadbeef", BansheeBackupFile.openPem(json, pem, "RLRLRL".toCharArray()).fingerprint());
    }

    @Test
    void wrongPemRejected() throws Exception {
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), rsaPem(), "LRLRLR".toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.openPem(json, rsaPem(), "LRLRLR".toCharArray()));
        assertTrue(err.getMessage().contains("Wrong signing key"));
    }

    @Test
    void passphraseV3StillOpens() throws Exception {
        String json = BansheeBackupFile.seal("aabbccdd", "legacy-clone", "secret".toCharArray());
        assertEquals(3, BansheeBackupFile.peekVersion(json));
        BansheeBackupFile.Opened opened = BansheeBackupFile.open(json, "secret".toCharArray());
        assertEquals("aabbccdd", opened.fingerprint());
        assertEquals("legacy-clone", opened.payload());
        assertNull(opened.oracle());
    }

    @Test
    void pemOpenRejectsPassphraseBackup() throws Exception {
        String json = BansheeBackupFile.seal("aabbccdd", "legacy-clone", "secret".toCharArray());
        assertThrows(IllegalArgumentException.class, () -> BansheeBackupFile.openPem(json, rsaPem()));
    }

    @Test
    void passphraseOpenRejectsPemBackup() throws Exception {
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), rsaPem(), "LRLRLR".toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.open(json, "secret".toCharArray()));
        assertTrue(err.getMessage().contains(".pem"));
    }

    @Test
    void pemV4StillOpensWithoutSequence() throws Exception {
        String pem = rsaPem();
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), pem);
        assertEquals(4, BansheeBackupFile.peekVersion(json));
        assertEquals("deadbeef", BansheeBackupFile.openPem(json, pem).fingerprint());
    }

    @Test
    void wrongSequenceRejected() throws Exception {
        String pem = rsaPem();
        String json = BansheeBackupFile.seal("deadbeef", "Y2xvbmU=", emptyOracle(), pem, "LRLRLR".toCharArray());
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.openPem(json, pem, "RLRLRL".toCharArray()));
        assertTrue(err.getMessage().contains("Wrong unlock sequence"));
    }

    @Test
    void studioV2Rejected() throws Exception {
        String json = """
                {"format":"banshee-backup","version":2,"fingerprint":"deadbeef","keyId":"0123456789abcdef","iv":"AA==","ciphertext":"AA=="}
                """;
        IllegalArgumentException err = assertThrows(IllegalArgumentException.class,
                () -> BansheeBackupFile.openPem(json, rsaPem()));
        assertTrue(err.getMessage().contains("Studio"));
    }

    private static BansheeOracle.Snapshot emptyOracle() {
        return new BansheeOracle.Snapshot(null, List.of());
    }

    private static String rsaPem() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey)g.generateKeyPair().getPrivate();
        String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + b64 + "\n-----END PRIVATE KEY-----\n";
    }
}
