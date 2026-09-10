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
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(68)).divide(new byte[1955], PACKET_CAPACITY);

        assertEquals(3, pieces.size());
        assertPiece("the head", 0, 68, pieces.get(0));
        assertPiece("the tail, which the capture starts at 1048", 1048, 907, pieces.get(1));
        assertPiece("the middle, which is the second packet", 68, 980, pieces.get(2));
    }

    /** Capture 24d06d79d2924cd1: 1947 bytes, 971 and 976, first frame 73, tail from 1049. */
    public void testItReproducesTheOtherCapturedDivision() {
        List<InitialCryptoDivision.Piece> pieces =
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(73)).divide(new byte[1947], PACKET_CAPACITY);

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
            int firstFrame = division.divide(new byte[1955], PACKET_CAPACITY).get(0).length;
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
                .divide(new byte[800], PACKET_CAPACITY).isEmpty());
    }

    private static void assertHalves(int total, int first, int second) {
        List<InitialCryptoDivision.Piece> pieces =
                new InitialCryptoDivision.ChromeMultiPacket(fixedFirstFrame(68)).divide(new byte[total], PACKET_CAPACITY);
        assertEquals("first packet of " + total, first, pieces.get(0).length + pieces.get(1).length);
        assertEquals("second packet of " + total, second, pieces.get(2).length);
    }

    private static void assertPiece(String what, int offset, int length, InitialCryptoDivision.Piece piece) {
        assertEquals(what + " offset", offset, piece.offset);
        assertEquals(what + " length", length, piece.length);
    }

    /**
     * Firefox's, from the two captured connections in docs/captures/firefox-155-quic-initial.pcapng.
     * Both cut at the middle of the server name and both fill their packets evenly, and the cut lands
     * in a completely different place each time because Firefox permutes its extensions - so the same
     * host name sits at a different offset every connection.
     */
    public void testItReproducesFirefoxsCapturedSlicing() {
        // 1912 bytes cut at 109: the first packet takes 847 bytes from 1065, then the first 109.
        assertSlicing(1912, 109, 1065, 847, 109, 956);
        // 1904 bytes cut at 486: 466 bytes from 1438, then the first 486.
        assertSlicing(1904, 486, 1438, 466, 486, 952);
    }

    /**
     * A cut past the middle, which neither capture shows and which neqo handles all the same: the
     * right chunk fits, so the packet takes it whole and as much of the left as is left over.
     * <p>
     * Worth having because the first version of this refused the case outright, and refusing it showed
     * up as one connection in three sending an undivided ClientHello - the shape Firefox never sends.
     * neqo's limit_chunks has no such branch, so neither does this.
     */
    public void testACutPastTheMiddleStillSlices() {
        List<InitialCryptoDivision.Piece> pieces = new InitialCryptoDivision.NeqoSniSlicing()
                .divide(helloWithServerNameMidpointAt(1900, 1200), 1200);

        assertFalse("a ClientHello whose name sits late must still be sliced", pieces.isEmpty());
        assertEquals("the right chunk fits whole", 700, pieces.get(0).length);
        assertEquals("so the packet takes what is left of its allowance from the left", 250,
                pieces.get(1).length);
    }

    /** No server name, so nothing to cut through: neqo writes the flight whole and so does this. */
    public void testAFlightWithNoServerNameIsLeftAlone() {
        assertTrue(new InitialCryptoDivision.NeqoSniSlicing()
                .divide(new byte[1900], 1200).isEmpty());
    }

    private static void assertSlicing(int total, int mid, int rightOffset, int rightLength,
                                      int leftLength, int firstPacket) {
        List<InitialCryptoDivision.Piece> pieces = new InitialCryptoDivision.NeqoSniSlicing()
                .divide(helloWithServerNameMidpointAt(total, mid), 1200);

        assertPiece("the tail of the right chunk", rightOffset, rightLength, pieces.get(0));
        assertPiece("the left chunk", 0, leftLength, pieces.get(1));
        assertEquals("the first packet holds an even half", firstPacket, rightLength + leftLength);
        assertEquals("and the rest follows in order", total - firstPacket,
                pieces.get(2).length + (pieces.size() > 3 ? pieces.get(3).length : 0));
    }

    /**
     * A ClientHello of {@code total} bytes whose host name has its midpoint at {@code mid}, which is
     * the only thing about it the slicing reads. The name is 22 bytes, the length of the one the
     * captures were taken against, and a padding extension before it puts it where it is wanted -
     * which is how a permuted extension order moves it in a real one.
     */
    private static byte[] helloWithServerNameMidpointAt(int total, int mid) {
        byte[] hello = new byte[total];
        int nameLength = 22;
        int serverName = mid - nameLength / 2 - 9;   // where the extension starts
        put16(hello, 39, 2);                        // cipher_suites length, one suite
        hello[43] = 1;                              // one compression method
        put16(hello, 47 - 2, total - 47);           // extensions length, to the end
        int filler = serverName - 47 - 4;
        put16(hello, 47, 21);                       // padding extension before it
        put16(hello, 49, filler);
        put16(hello, serverName, 0);                // server_name
        put16(hello, serverName + 2, nameLength + 5);
        put16(hello, serverName + 4, nameLength + 3);
        put16(hello, serverName + 7, nameLength);
        int after = serverName + 9 + nameLength;
        put16(hello, after, 21);                    // padding extension after it, to the end
        put16(hello, after + 2, total - after - 4);
        return hello;
    }

    private static void put16(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >> 8);
        data[offset + 1] = (byte) value;
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
