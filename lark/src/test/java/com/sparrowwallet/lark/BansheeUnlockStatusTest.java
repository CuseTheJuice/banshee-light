// Banshee Light. Apache License 2.0. See LICENSE and NOTICE.
package com.sparrowwallet.lark;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BansheeUnlockStatusTest {
    @Test
    void parseOracleLocked() {
        BansheeUnlockStatus st = BansheeUnlockStatus.parse("UNLOCK unlock=1 locked=1 fails=2 oracle=1 session=1");
        assertTrue(st.configured());
        assertTrue(st.locked());
        assertTrue(st.oracle());
        assertTrue(st.session());
        assertEquals(2, st.fails());
        assertEquals("1 of 3 tries remaining", st.remainingTries());
    }

    @Test
    void parseLegacyNoOracleFlag() {
        BansheeUnlockStatus st = BansheeUnlockStatus.parse("UNLOCK unlock=1 locked=0 fails=0");
        assertTrue(st.configured());
        assertFalse(st.locked());
        assertFalse(st.oracle());
        assertFalse(st.session());
        assertEquals("3 of 3 tries remaining", st.remainingTries());
    }
}
