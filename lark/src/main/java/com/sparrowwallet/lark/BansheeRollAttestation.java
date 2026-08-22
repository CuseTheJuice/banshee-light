// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

public record BansheeRollAttestation(String hmac, String transcriptSha256, String entropySha256,
                                     int totalBits, int usedBits, int wordCount, boolean legacy) {
    public static BansheeRollAttestation parse(String rest) {
        String t = rest == null ? "" : rest.trim();
        if(t.matches("(?i)[0-9a-f]{64}")) {
            return new BansheeRollAttestation(t.toLowerCase(), "", "", 0, 256, 0, true);
        }
        String hmac = "";
        String tsha = "";
        String esha = "";
        int bits = 0;
        int used = 256;
        int n = 0;
        for(String part : t.split("\\s+")) {
            int eq = part.indexOf('=');
            if(eq < 0) {
                continue;
            }
            String key = part.substring(0, eq);
            String val = part.substring(eq + 1).trim().toLowerCase();
            switch(key) {
                case "hmac" -> hmac = val;
                case "tsha" -> tsha = val;
                case "esha" -> esha = val;
                case "bits" -> bits = parseInt(val);
                case "used" -> used = parseInt(val);
                case "n" -> n = parseInt(val);
            }
        }
        boolean legacy = hmac.isEmpty() && t.matches("(?i)[0-9a-f]{64}.*");
        if(hmac.isEmpty() && t.length() >= 64) {
            hmac = t.substring(0, 64).toLowerCase();
        }
        return new BansheeRollAttestation(hmac, tsha, esha, bits, used, n, legacy);
    }

    private static int parseInt(String val) {
        try {
            return Integer.parseInt(val);
        } catch(NumberFormatException e) {
            return 0;
        }
    }
}
