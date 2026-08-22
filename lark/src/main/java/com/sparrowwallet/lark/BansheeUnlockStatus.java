// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public record BansheeUnlockStatus(boolean configured, boolean locked, int fails, boolean oracle, boolean session) {
    private static final Pattern FAILS = Pattern.compile("fails=(\\d+)");

    public static BansheeUnlockStatus parse(String rest) {
        String line = rest == null ? "" : rest;
        Matcher m = FAILS.matcher(line);
        return new BansheeUnlockStatus(
                line.contains("unlock=1"),
                line.contains("locked=1"),
                m.find() ? Integer.parseInt(m.group(1)) : 0,
                line.contains("oracle=1"),
                line.contains("session=1"));
    }

    public String remainingTries() {
        int left = Math.max(0, 3 - fails);
        return left + " of 3 tries remaining";
    }
}
