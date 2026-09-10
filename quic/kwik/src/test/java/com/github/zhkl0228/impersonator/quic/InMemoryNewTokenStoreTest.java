package com.github.zhkl0228.impersonator.quic;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * How address validation tokens are handed out between connections, which RFC 9000 section 8.1.3
 * says more about than it might seem: which one to send, how often, and to whom.
 */
public class InMemoryNewTokenStoreTest extends TestCase {

    private final NewTokenStore store = new InMemoryNewTokenStore();

    /** "sending the most recent unused token is most likely to be effective". */
    public void testItHandsOutTheNewestFirst() {
        store.put("example.com", Arrays.asList(token(1), token(2), token(3)));

        assertEquals(3, store.take("example.com")[0]);
        assertEquals(2, store.take("example.com")[0]);
        assertEquals(1, store.take("example.com")[0]);
    }

    /**
     * "A client SHOULD NOT reuse a token from a NEW_TOKEN frame for different connection attempts.
     * Reusing a token allows connections to be linked by entities on the network path."
     */
    public void testATokenIsUsedOnce() {
        store.put("example.com", Collections.singletonList(token(1)));

        assertNotNull(store.take("example.com"));
        assertNull("a token handed to one connection must not be handed to the next",
                store.take("example.com"));
    }

    /**
     * "A client MUST NOT include a token that is not applicable to the server that it is connecting
     * to." This keeps them by host, which is the narrow reading: a token is applicable to any server
     * the connection is authoritative for, and this does not try to work out which those are.
     */
    public void testTokensDoNotCrossHosts() {
        store.put("example.com", Collections.singletonList(token(1)));

        assertNull(store.take("example.org"));
        assertNotNull(store.take("example.com"));
    }

    /** Nothing to keep is not something to keep: a server that issues none leaves no entry. */
    public void testAConnectionThatWasGivenNoneKeepsNone() {
        store.put("example.com", new ArrayList<>());
        store.put("example.org", null);

        assertNull(store.take("example.com"));
        assertNull(store.take("example.org"));
    }

    /**
     * Bounded per host, oldest dropped: "clients can regard older tokens as being less likely to be
     * useful to the server for address validation".
     */
    public void testTheOldestAreDroppedWhenThereAreTooMany() {
        List<byte[]> tokens = new ArrayList<>();
        for (int i = 1; i <= 12; i++) {
            tokens.add(token(i));
        }
        store.put("example.com", tokens);

        assertEquals("the newest is still there", 12, store.take("example.com")[0]);
        for (int i = 11; i >= 5; i--) {
            assertEquals(i, store.take("example.com")[0]);
        }
        assertNull("the four oldest were dropped rather than kept for ever", store.take("example.com"));
    }

    private static byte[] token(int id) {
        return new byte[] { (byte) id, 0x42 };
    }
}
