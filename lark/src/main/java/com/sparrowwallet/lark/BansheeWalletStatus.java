// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record BansheeWalletStatus(boolean ready, String fingerprint, boolean unlock, boolean locked) {
    private static final Pattern FP = Pattern.compile("fingerprint=([0-9a-fA-F]{8})");

    public static BansheeWalletStatus parse(String rest) {
        String line = rest == null ? "" : rest;
        Matcher fp = FP.matcher(line);
        return new BansheeWalletStatus(
                line.contains("ready=1"),
                fp.find() ? fp.group(1) : "",
                line.contains("unlock=1"),
                line.contains("locked=1"));
    }
}
