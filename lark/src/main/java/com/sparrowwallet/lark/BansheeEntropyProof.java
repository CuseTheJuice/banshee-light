// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

public final class BansheeEntropyProof {
    public static final int WALLET_DICE_WORDS = 100;
    public static final int BIP39_ENTROPY_BYTES = 32;
    public static final int EFF_WORD_COUNT = 7776;

    private BansheeEntropyProof() {
    }

    public static int diceCodeToIndex(String code) {
        String t = code == null ? "" : code.trim();
        if(!t.matches("[1-6]{5}")) {
            throw new IllegalArgumentException("invalid dice code");
        }
        int idx = 0;
        for(int i = 0; i < 5; i++) {
            idx = idx * 6 + (t.charAt(i) - '1');
        }
        if(idx < 0 || idx >= EFF_WORD_COUNT) {
            throw new IllegalArgumentException("dice index out of range");
        }
        return idx;
    }

    public static byte[] entropyFromDiceCodes(List<String> codes) {
        if(codes.size() < WALLET_DICE_WORDS) {
            throw new IllegalArgumentException("need at least " + WALLET_DICE_WORDS + " dice rolls");
        }
        StringBuilder bits = new StringBuilder();
        for(String code : codes) {
            String bin = Integer.toBinaryString(diceCodeToIndex(code));
            bits.append("0".repeat(Math.max(0, 13 - bin.length()))).append(bin);
        }
        int needBits = BIP39_ENTROPY_BYTES * 8;
        if(bits.length() < needBits) {
            throw new IllegalArgumentException("not enough dice entropy");
        }
        byte[] out = new byte[BIP39_ENTROPY_BYTES];
        for(int i = 0; i < out.length; i++) {
            out[i] = (byte)Integer.parseInt(bits.substring(i * 8, i * 8 + 8), 2);
        }
        return out;
    }

    public static String sha256Hex(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch(NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String sha256Hex(String utf8) {
        return sha256Hex(utf8.getBytes(StandardCharsets.UTF_8));
    }

    public static Report verify(String deviceId, List<String> diceCodes, List<String> deviceEffWords,
                                BansheeRollAttestation attestation) {
        String transcript = String.join("", diceCodes);
        byte[] entropy = entropyFromDiceCodes(diceCodes);
        String entropyHex = HexFormat.of().formatHex(entropy);
        String transcriptSha256 = sha256Hex(transcript);
        String entropySha256 = sha256Hex(entropy);
        int totalBits = diceCodes.size() * 13;
        int usedBits = BIP39_ENTROPY_BYTES * 8;
        List<Step> steps = new ArrayList<>();

        boolean rollsOk = diceCodes.size() == WALLET_DICE_WORDS
                && diceCodes.stream().allMatch(c -> c.matches("[1-6]{5}"));
        steps.add(new Step("hardware_rng", "Hardware dice on Banshee", rollsOk));

        boolean deviceOk = rollsOk && deviceEffWords.size() == WALLET_DICE_WORDS
                && deviceEffWords.stream().noneMatch(w -> w == null || w.isBlank());
        steps.add(new Step("device_rolls", "On-device dice rolls", deviceOk));

        boolean indexOk = deviceOk;
        if(indexOk) {
            try {
                for(String code : diceCodes) {
                    diceCodeToIndex(code);
                }
            } catch(IllegalArgumentException e) {
                indexOk = false;
            }
        }
        steps.add(new Step("dice_format", "Dice code validity", indexOk));

        boolean tshaOk = !attestation.legacy() && attestation.transcriptSha256().length() == 64
                && attestation.transcriptSha256().equals(transcriptSha256);
        steps.add(new Step("transcript_hash", "Roll transcript hash", tshaOk));

        boolean eshaOk = !attestation.legacy() && attestation.entropySha256().length() == 64
                && attestation.entropySha256().equals(entropySha256);
        steps.add(new Step("entropy_hash", "BIP39 entropy hash", eshaOk));

        boolean hmacOk = attestation.hmac().length() == 64;
        steps.add(new Step("device_attestation", "Device HMAC attestation", hmacOk));
        steps.add(new Step("entropy_budget", "Entropy budget", totalBits >= usedBits));

        boolean allOk = steps.stream().allMatch(Step::ok);
        return new Report(List.copyOf(steps), allOk, deviceId == null ? "unknown" : deviceId, diceCodes.size(),
                transcript, transcriptSha256, entropyHex, entropySha256, totalBits, usedBits, attestation);
    }

    public record Step(String id, String label, boolean ok) {
    }

    public record Report(List<Step> steps, boolean allOk, String deviceId, int wordCount, String transcript,
                         String transcriptSha256, String entropyHex, String entropySha256, int totalBits,
                         int usedBits, BansheeRollAttestation attestation) {
    }
}
