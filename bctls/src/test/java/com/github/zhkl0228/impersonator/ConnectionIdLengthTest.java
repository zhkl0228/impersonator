package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;

import java.util.SortedMap;
import java.util.TreeMap;

/**
 * The Destination Connection ID length each profile puts in its first Initial packet.
 * <p>
 * Two of the three send a fixed eight, and Firefox draws one per connection - which is neqo's
 * {@code ConnectionId::generate_initial}, {@code max(8, 5 + (v & (v >> 4)))} for a random byte v. Four
 * captured Firefox connections gave 8, 13, 14 and 19, and a client that always sent the same length
 * would be identifiable by the one thing that is supposed to vary.
 * <p>
 * Asserted here, from the profile, rather than over connections to an endpoint. The HTTP/3 test that
 * used to ask this of eight live connections was asking a question about a distribution with eight
 * samples: the length is 8 about nine times in sixteen, so eight connections come out the same about
 * one run in a hundred, and that is what it did. A thousand draws cost nothing and settle it.
 */
public class ConnectionIdLengthTest extends TestCase {

    private static final int DRAWS = 1000;

    /** neqo's, which is the only one of the three that is a draw at all. */
    public void testFirefoxDrawsItPerConnection() {
        SortedMap<Integer, Integer> drawn = draw(ImpersonatorFactory.macFirefox());

        assertTrue("a length that never varies is the tell this exists to avoid: " + drawn,
                drawn.size() > 1);
        assertEquals("neqo cannot produce anything below 8", 8, (int) drawn.firstKey());
        assertEquals("nor anything above 20, which is 5 + 15", 20, (int) drawn.lastKey());
    }

    /**
     * And the shape of it, not only that it moves. {@code v & (v >> 4)} is the low nibble of a random
     * byte AND its high nibble, so each bit survives a quarter of the time and the result is 3 or less
     * - which is to say the length is 8 - with probability (3/4)^2, nine times in sixteen.
     */
    public void testEightIsPickedNineTimesInSixteen() {
        SortedMap<Integer, Integer> drawn = draw(ImpersonatorFactory.macFirefox());
        double eights = drawn.getOrDefault(8, 0) / (double) DRAWS;

        assertTrue("8 should come up about 0.5625 of the time, got " + eights + " in " + drawn,
                eights > 0.50 && eights < 0.62);
    }

    /** Chrome and Safari send eight every time, which their captures show and which is not a draw. */
    public void testTheOthersDoNotDrawAtAll() {
        assertEquals("{8=" + DRAWS + "}", draw(ImpersonatorFactory.macChrome()).toString());
        assertEquals("{8=" + DRAWS + "}", draw(ImpersonatorFactory.macSafari()).toString());
    }

    /**
     * How many of each length a profile produces over {@link #DRAWS} connections' worth of asking.
     * <p>
     * A fresh QuicTransport each time, because that is what a connection gets: the profile is asked
     * for one per connection, and the length is asked of it once, so anything that drew the length
     * earlier than that - when the profile was built, say - would show up here as one value.
     */
    private static SortedMap<Integer, Integer> draw(ImpersonatorApi api) {
        SortedMap<Integer, Integer> counts = new TreeMap<>();
        for (int i = 0; i < DRAWS; i++) {
            QuicTransport transport = ((Impersonator) api).getQuicTransport();
            counts.merge(transport.getDestinationConnectionIdLength().getAsInt(), 1, Integer::sum);
        }
        return counts;
    }
}
