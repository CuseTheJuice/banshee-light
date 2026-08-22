// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

public record BansheeRollWord(String dice, String effWord) {
    public static BansheeRollWord parse(String rest) {
        String[] parts = rest.trim().split("\\s+");
        String dice = parts.length > 0 ? parts[0] : "";
        StringBuilder word = new StringBuilder();
        for(int i = 0; i < parts.length; i++) {
            if("WORD".equals(parts[i]) && i + 1 < parts.length) {
                for(int j = i + 1; j < parts.length; j++) {
                    if(word.length() > 0) {
                        word.append(' ');
                    }
                    word.append(parts[j]);
                }
                break;
            }
        }
        return new BansheeRollWord(dice, word.toString().trim());
    }
}
