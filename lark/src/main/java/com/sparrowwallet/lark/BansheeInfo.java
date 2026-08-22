// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.util.LinkedHashMap;
import java.util.Map;

public record BansheeInfo(Map<String, String> fields) {
    public static BansheeInfo parse(String rest) {
        Map<String, String> fields = new LinkedHashMap<>();
        String line = rest == null ? "" : rest.trim();
        if(line.startsWith("INFO ")) {
            line = line.substring(5).trim();
        }
        for(String part : line.split("\\s+")) {
            int eq = part.indexOf('=');
            if(eq > 0) {
                fields.put(part.substring(0, eq), part.substring(eq + 1));
            }
        }
        return new BansheeInfo(fields);
    }

    public String get(String key) {
        return fields.getOrDefault(key, "");
    }

    public boolean secureBoot() {
        return "1".equals(get("secureBoot"));
    }

    public boolean flashEnc() {
        return "1".equals(get("flashEnc"));
    }

    public boolean walletReady() {
        return "1".equals(get("wallet"));
    }

    public boolean unlockConfigured() {
        return "1".equals(get("unlock"));
    }

    public boolean locked() {
        return "1".equals(get("locked"));
    }

    public boolean oracleRegistered() {
        return "1".equals(get("oracle"));
    }

    public BansheeUnlockStatus asUnlockStatus() {
        return new BansheeUnlockStatus(unlockConfigured(), locked(), 0, oracleRegistered(), "1".equals(get("session")));
    }

    public BansheeWalletStatus asWalletStatus() {
        String fp = get("fingerprint");
        return new BansheeWalletStatus(walletReady(), fp == null ? "" : fp, unlockConfigured(), locked());
    }

    public String version() {
        return get("version");
    }

    public String deviceId() {
        return get("deviceId");
    }
}
