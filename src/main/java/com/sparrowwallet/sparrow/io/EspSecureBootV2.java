// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.sparrow.io;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.zip.CRC32;

/**
 * ESP Secure Boot v2 RSA-3072 image signing (same layout as {@code espsecure sign_data --version 2}).
 */
public final class EspSecureBootV2 {
    static final int SECTOR_SIZE = 4096;
    static final int SIG_BLOCK_SIZE = 1216;
    private static final int RSA_BYTES = 384;
    private static final byte MAGIC = (byte)0xE7;
    private static final byte VERSION_RSA = 0x02;
    private static final byte[] RSA_ALG_ID = hex("300d06092a864886f70d0101010500");

    private EspSecureBootV2() {
    }

    public static byte[] sign(byte[] image, Path pem) throws IOException {
        try {
            return sign(image, loadKey(Files.readString(pem)));
        } catch(GeneralSecurityException e) {
            throw new IOException("Could not sign with " + pem.getFileName() + ": " + e.getMessage(), e);
        }
    }

    static byte[] sign(byte[] image, RSAPrivateCrtKey key) throws GeneralSecurityException {
        if(key.getModulus().bitLength() != 3072) {
            throw new GeneralSecurityException("Secure Boot v2 needs RSA-3072 (this key is "
                    + key.getModulus().bitLength() + " bits)");
        }
        byte[] contents = padToSector(image);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(contents);
        byte[] signature = rsaPss(key, contents);
        byte[] block = rsaBlock(digest, key, signature);
        byte[] sector = new byte[SECTOR_SIZE];
        Arrays.fill(sector, (byte)0xFF);
        System.arraycopy(block, 0, sector, 0, block.length);
        byte[] out = new byte[contents.length + SECTOR_SIZE];
        System.arraycopy(contents, 0, out, 0, contents.length);
        System.arraycopy(sector, 0, out, contents.length, SECTOR_SIZE);
        return out;
    }

    private static byte[] padToSector(byte[] image) {
        int rem = image.length % SECTOR_SIZE;
        if(rem == 0) {
            return image;
        }
        byte[] padded = new byte[image.length + (SECTOR_SIZE - rem)];
        System.arraycopy(image, 0, padded, 0, image.length);
        Arrays.fill(padded, image.length, padded.length, (byte)0xFF);
        return padded;
    }

    private static byte[] rsaPss(RSAPrivateCrtKey key, byte[] contents) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        sig.initSign(key);
        sig.update(contents);
        return sig.sign();
    }

    private static byte[] rsaBlock(byte[] digest, RSAPrivateCrtKey key, byte[] signature) {
        BigInteger n = key.getModulus();
        BigInteger e = key.getPublicExponent();
        BigInteger rinv = BigInteger.ONE.shiftLeft(key.getModulus().bitLength() * 2).mod(n);
        BigInteger mask32 = BigInteger.ONE.shiftLeft(32);
        int mprime = n.mod(mask32).modInverse(mask32).negate().mod(mask32).intValue();

        ByteBuffer buf = ByteBuffer.allocate(SIG_BLOCK_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        buf.put(MAGIC);
        buf.put(VERSION_RSA);
        buf.putShort((short)0);
        buf.put(digest);
        buf.put(toLittleEndian(n, RSA_BYTES));
        buf.putInt(e.intValue());
        buf.put(toLittleEndian(rinv, RSA_BYTES));
        buf.putInt(mprime);
        buf.put(reverse(signature, RSA_BYTES));
        CRC32 crc = new CRC32();
        crc.update(buf.array(), 0, 1196);
        buf.putInt((int)crc.getValue());
        buf.put(new byte[16]);
        return buf.array();
    }

    public static String generateSigningKeyPem() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072, new SecureRandom());
        RSAPrivateCrtKey key = (RSAPrivateCrtKey)g.generateKeyPair().getPrivate();
        return toPkcs1Pem(key);
    }

    static String toPkcs1Pem(RSAPrivateCrtKey key) {
        byte[] der = derSequence(concat(
                derInteger(BigInteger.ZERO),
                derInteger(key.getModulus()),
                derInteger(key.getPublicExponent()),
                derInteger(key.getPrivateExponent()),
                derInteger(key.getPrimeP()),
                derInteger(key.getPrimeQ()),
                derInteger(key.getPrimeExponentP()),
                derInteger(key.getPrimeExponentQ()),
                derInteger(key.getCrtCoefficient())));
        String b64 = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN RSA PRIVATE KEY-----\n" + b64 + "\n-----END RSA PRIVATE KEY-----\n";
    }

    public static RSAPrivateCrtKey parsePem(String pem) throws GeneralSecurityException, IOException {
        return loadKey(pem);
    }

    public static byte[] pssSign(RSAPrivateCrtKey key, byte[] message) throws GeneralSecurityException {
        return rsaPss(key, message);
    }

    public static boolean pssVerify(RSAPrivateCrtKey key, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature sig = Signature.getInstance("RSASSA-PSS");
        sig.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        RSAPublicKey pub = (RSAPublicKey)KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(key.getModulus(), key.getPublicExponent()));
        sig.initVerify(pub);
        sig.update(message);
        return sig.verify(signature);
    }

    static RSAPrivateCrtKey loadKey(String pem) throws GeneralSecurityException, IOException {
        String body = pem.replace("\r", "");
        if(body.contains("BEGIN RSA PRIVATE KEY")) {
            byte[] pkcs1 = decodePem(body, "RSA PRIVATE KEY");
            try {
                return parsePkcs1(pkcs1);
            } catch(IOException ignored) {
                return (RSAPrivateCrtKey)KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(wrapPkcs8(pkcs1)));
            }
        }
        if(body.contains("BEGIN PRIVATE KEY")) {
            byte[] der = decodePem(body, "PRIVATE KEY");
            return (RSAPrivateCrtKey)KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        }
        throw new IOException("Not an unencrypted RSA PEM (BEGIN RSA PRIVATE KEY / BEGIN PRIVATE KEY)");
    }

    private static RSAPrivateCrtKey parsePkcs1(byte[] der) throws GeneralSecurityException, IOException {
        DerCursor cur = new DerCursor(der);
        DerCursor seq = cur.readSequence();
        seq.readInteger();
        BigInteger n = seq.readInteger();
        BigInteger e = seq.readInteger();
        BigInteger d = seq.readInteger();
        BigInteger p = seq.readInteger();
        BigInteger q = seq.readInteger();
        BigInteger dp = seq.readInteger();
        BigInteger dq = seq.readInteger();
        BigInteger qi = seq.readInteger();
        RSAPrivateCrtKeySpec spec = new RSAPrivateCrtKeySpec(n, e, d, p, q, dp, dq, qi);
        return (RSAPrivateCrtKey)KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static byte[] wrapPkcs8(byte[] pkcs1) {
        byte[] version = {0x02, 0x01, 0x00};
        byte[] octet = derOctetString(pkcs1);
        return derSequence(concat(version, RSA_ALG_ID, octet));
    }

    private static byte[] decodePem(String pem, String type) throws IOException {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int a = pem.indexOf(begin);
        int b = pem.indexOf(end);
        if(a < 0 || b < 0) {
            throw new IOException("PEM is missing " + type + " block");
        }
        String b64 = pem.substring(a + begin.length(), b).replaceAll("\\s+", "");
        return Base64.getDecoder().decode(b64.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] toLittleEndian(BigInteger value, int len) {
        byte[] be = value.toByteArray();
        int start = (be.length > 0 && be[0] == 0) ? 1 : 0;
        int srcLen = be.length - start;
        if(srcLen > len) {
            throw new IllegalArgumentException("Integer does not fit in " + len + " bytes");
        }
        byte[] out = new byte[len];
        for(int i = 0; i < srcLen; i++) {
            out[i] = be[be.length - 1 - i];
        }
        return out;
    }

    private static byte[] reverse(byte[] be, int len) {
        byte[] padded = new byte[len];
        if(be.length > len) {
            throw new IllegalArgumentException("RSA signature longer than " + len + " bytes");
        }
        System.arraycopy(be, 0, padded, len - be.length, be.length);
        byte[] out = new byte[len];
        for(int i = 0; i < len; i++) {
            out[i] = padded[len - 1 - i];
        }
        return out;
    }

    private static byte[] derInteger(BigInteger value) {
        byte[] mag = value.toByteArray();
        return concat(new byte[] {0x02}, derLen(mag.length), mag);
    }

    private static byte[] derSequence(byte[] body) {
        return concat(new byte[] {0x30}, derLen(body.length), body);
    }

    private static byte[] derOctetString(byte[] body) {
        return concat(new byte[] {0x04}, derLen(body.length), body);
    }

    private static byte[] derLen(int len) {
        if(len < 0x80) {
            return new byte[] {(byte)len};
        }
        if(len <= 0xFF) {
            return new byte[] {(byte)0x81, (byte)len};
        }
        return new byte[] {(byte)0x82, (byte)(len >> 8), (byte)len};
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for(byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int o = 0;
        for(byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for(int i = 0; i < out.length; i++) {
            out[i] = (byte)Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static final class DerCursor {
        private final byte[] data;
        private int pos;

        DerCursor(byte[] data) {
            this.data = data;
        }

        DerCursor readSequence() throws IOException {
            expect(0x30);
            int len = readLen();
            byte[] body = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return new DerCursor(body);
        }

        BigInteger readInteger() throws IOException {
            expect(0x02);
            int len = readLen();
            byte[] body = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            return new BigInteger(body);
        }

        private void expect(int tag) throws IOException {
            if(pos >= data.length || (data[pos] & 0xFF) != tag) {
                throw new IOException("Unexpected DER tag");
            }
            pos++;
        }

        private int readLen() throws IOException {
            int b = data[pos++] & 0xFF;
            if(b < 0x80) {
                return b;
            }
            int n = b & 0x7F;
            int len = 0;
            for(int i = 0; i < n; i++) {
                len = (len << 8) | (data[pos++] & 0xFF);
            }
            return len;
        }
    }
}
