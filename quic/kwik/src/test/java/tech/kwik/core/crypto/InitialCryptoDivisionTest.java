package tech.kwik.core.crypto;

import junit.framework.TestCase;

import java.util.List;
import java.util.Random;

/**
 * Chrome's division of its ClientHello between its two Initial packets, checked against the four
 * captured connections in docs/captures/chrome-152-quic-initial.pcapng.
 * <p>
 * Worth pinning here rather than only against a live endpoint, because the fingerprint endpoint
 * reports the frame types of the first Initial and not the offsets those frames carry - and the
 * offsets are the whole point. A division that produced the right number of CRYPTO frames in the
 * wrong places would pass every network test and still be reassembled by any reader that just walks
 * the datagram in order, which is the thing Chrome's layout exists to defeat.
 */
public class InitialCryptoDivisionTest extends TestCase {

    /** One Initial holds this much CRYPTO payload; the exact value only has to exceed a half. */
    private static final int PACKET_CAPACITY = 1200;

    /**
     * Capture 12fc1f0ce2195309: a 1955 byte ClientHello, 975 bytes in the first packet and 980 in the
     * second, the first frame 68 bytes and the tail starting at 1048.
     */
    public void testItReproducesTheCapturedDivision() {
        List<InitialCryptoDivision.Piece> pieces =
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(68)).divide(1955, PACKET_CAPACITY);

        assertEquals(3, pieces.size());
        assertPiece("the head", 0, 68, pieces.get(0));
        assertPiece("the tail, which the capture starts at 1048", 1048, 907, pieces.get(1));
        assertPiece("the middle, which is the second packet", 68, 980, pieces.get(2));
    }

    /** Capture 24d06d79d2924cd1: 1947 bytes, 971 and 976, first frame 73, tail from 1049. */
    public void testItReproducesTheOtherCapturedDivision() {
        List<InitialCryptoDivision.Piece> pieces =
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(73)).divide(1947, PACKET_CAPACITY);

        assertPiece("the head", 0, 73, pieces.get(0));
        assertPiece("the tail, which the capture starts at 1049", 1049, 898, pieces.get(1));
        assertPiece("the middle, which the capture puts at 976 bytes", 73, 976, pieces.get(2));
    }

    /**
     * The halves themselves, over all three captures whose totals are known. This is the rule the
     * captures agree on - {@code (total - 5) / 2} and the rest - stated apart from the random first
     * frame, which does not move them.
     */
    public void testTheHalvesAreTheOnesEveryCaptureShows() {
        assertHalves(1955, 975, 980);
        assertHalves(2163, 1079, 1084);
        assertHalves(1947, 971, 976);
    }

    /** The first frame is QUICHE's 55 plus a value under 32, so it never leaves 55..86. */
    public void testTheFirstFrameStaysInQuichesRange() {
        Random random = new Random(1);
        InitialCryptoDivision division = new InitialCryptoDivision.ChromeMultiPacket(random);
        for (int i = 0; i < 200; i++) {
            int firstFrame = division.divide(1955, PACKET_CAPACITY).get(0).length;
            assertTrue("first frame " + firstFrame + " is outside 55..86", firstFrame >= 55 && firstFrame <= 86);
        }
    }

    /**
     * A ClientHello that fits in one packet gets no division. Chrome's never does - it offers a
     * post-quantum key share, which alone is over 1200 bytes - so there is no capture of what it would
     * do, and inventing a shape for it would put one on the wire that nothing supports.
     */
    public void testAClientHelloThatFitsIsLeftAlone() {
        assertTrue(new InitialCryptoDivision.ChromeMultiPacket(new Random(1))
                .divide(800, PACKET_CAPACITY).isEmpty());
    }

    private static void assertHalves(int total, int first, int second) {
        List<InitialCryptoDivision.Piece> pieces =
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(68)).divide(total, PACKET_CAPACITY);
        assertEquals("first packet of " + total, first, pieces.get(0).length + pieces.get(1).length);
        assertEquals("second packet of " + total, second, pieces.get(2).length);
    }

    private static void assertPiece(String what, int offset, int length, InitialCryptoDivision.Piece piece) {
        assertEquals(what + " offset", offset, piece.offset);
        assertEquals(what + " length", length, piece.length);
    }

    /** A Random whose first nextInt(32) gives the first frame length the capture shows. */
    private static Random fixedFirstFrame(int firstFrameLength) {
        return new Random() {
            @Override
            public int nextInt(int bound) {
                return firstFrameLength - 55;
            }
        };
    }
}
