// Banshee additions to Lark. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

public final class BansheeEntropyReport {
    public final String proof;
    public final String rng;

    public BansheeEntropyReport(String proof, String rng) {
        this.proof = proof == null ? "" : proof.trim();
        this.rng = rng == null ? "" : rng.trim();
    }
}
