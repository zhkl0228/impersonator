package tech.kwik.qpack.impl;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * The prefixed integer of RFC 7541 section 5.1, which RFC 9204 section 4.1.1 uses unmodified and
 * requires to carry 62 bits.
 * <p>
 * Round trips rather than byte vectors, deliberately. Vectors written from reading the RFC would
 * assert that this agrees with how the RFC was read; that a value written comes back as itself is a
 * property, and it is the property both bugs found here broke. The two of them are pinned by name
 * below with the values that broke them, because both produced an encoding that reads back as
 * something else rather than an error, and neither is reachable from the values a small header
 * happens to use.
 */
public class PrefixedIntegerTest extends TestCase {

    /** The prefix lengths QPACK actually uses, from the representations in RFC 9204 section 4. */
    private static final int[] PREFIX_LENGTHS = { 3, 4, 5, 6, 7, 8 };

    public void testAValueWrittenComesBackAsItself() throws IOException {
        long[] values = { 0, 1, 6, 7, 14, 15, 30, 31, 62, 63, 126, 127, 254, 255, 256, 1337, 65535,
                1 << 20, Integer.MAX_VALUE };
        for (int prefixLength : PREFIX_LENGTHS) {
            for (long value : values) {
                assertRoundTrip(prefixLength, value);
            }
        }
    }

    /**
     * A remainder of exactly 128, which the continuation boundary used to write as one byte.
     * <p>
     * The loop ended on {@code remainder > 128} where RFC 7541 ends it on {@code >= 128}, so 128 was
     * written as the single byte 0x80 - which reads back as a continuation byte worth zero followed
     * by whatever came next, and what came next was the rest of the field section. The values here
     * are the smallest one per prefix length that hits it.
     */
    public void testARemainderOfExactlyOneHundredAndTwentyEightIsTwoBytes() throws IOException {
        for (int prefixLength : PREFIX_LENGTHS) {
            long maxPrefix = (1L << prefixLength) - 1;
            byte[] written = write(prefixLength, (byte) 0, maxPrefix + 128);

            assertEquals("prefix length " + prefixLength + ": 128 must not be written as one byte",
                    3, written.length);
            assertRoundTrip(prefixLength, maxPrefix + 128);
        }
    }

    /**
     * The 62 bit range RFC 9204 section 4.1.1 requires: "QPACK implementations MUST be able to decode
     * integers up to and including 62 bits long."
     * <p>
     * The parser shifted an {@code int} by up to 63 bits, which in Java wraps the shift distance
     * rather than producing zero, so every continuation byte past the fifth landed back on top of the
     * low bits and the value came out wrong - again silently. Anything at or above 2^32 needs a
     * factor over 31 and reaches it.
     */
    public void testItCarriesSixtyTwoBits() throws IOException {
        long[] values = { 1L << 32, (1L << 35) + 12345, 1L << 40, 1L << 61, (1L << 62) - 1 };
        for (int prefixLength : PREFIX_LENGTHS) {
            for (long value : values) {
                assertRoundTrip(prefixLength, value);
            }
        }
    }

    /**
     * And refuses what is past those 62 bits, rather than returning some other number.
     * <p>
     * Both ways a longer integer goes wrong here are silent. Java masks a shift distance to six bits,
     * so at 64 the continuation bytes start landing back on the low bits of the value, and the
     * addition itself wraps through the sign bit - so a peer sending more continuation bytes than the
     * encoding allows would have a value accepted that it never encoded. The last case is also the
     * only bound on the loop: a run of 0x80 bytes carries no bits at all and used to be read for as
     * long as it lasted.
     */
    public void testItRefusesMoreThanSixtyTwoBits() throws IOException {
        for (int prefixLength : PREFIX_LENGTHS) {
            assertRefused(prefixLength, write(prefixLength, (byte) 0, 1L << 62));
            assertRefused(prefixLength, write(prefixLength, (byte) 0, Long.MAX_VALUE));

            // Continuation bytes that never stop: all bits set, and all bits clear.
            byte[] ones = new byte[64];
            Arrays.fill(ones, (byte) 0xff);
            assertRefused(prefixLength, ones);
            byte[] zeroes = new byte[64];
            Arrays.fill(zeroes, (byte) 0x80);
            zeroes[0] = (byte) 0xff;
            assertRefused(prefixLength, zeroes);
        }
    }

    private static void assertRefused(int prefixLength, byte[] encoded) {
        try {
            long parsed = PrefixedInteger.parsePrefixedInteger(prefixLength, new ByteArrayInputStream(encoded));
            fail("prefix length " + prefixLength + ": an integer past 62 bits was read as " + parsed);
        }
        catch (HttpQPackDecompressionFailedException | IOException refused) {
            // What it is for.
        }
    }

    /** The bits above the prefix are the instruction, and writing a value must not disturb them. */
    public void testThePrefixBitsSurviveTheValue() throws IOException {
        // Section Acknowledgment is 1 in the top bit and a 7 bit index; Insert Count Increment is
        // 00 and a 6 bit index. Both are written through this.
        assertEquals(0x84, write(7, (byte) 0x80, 4)[0] & 0xff);
        assertEquals(0x01, write(6, (byte) 0x00, 1)[0] & 0xff);
        // And a value that fills the prefix keeps them too, the continuation being what follows.
        assertEquals(0xff, write(7, (byte) 0x80, 200)[0] & 0xff);
    }

    /** The ByteBuffer variant the encoder writes through, which has the same boundary. */
    public void testTheBufferVariantRoundTripsToo() throws IOException {
        for (int prefixLength : PREFIX_LENGTHS) {
            int maxPrefix = (1 << prefixLength) - 1;
            for (int value : new int[] { 0, 1, maxPrefix - 1, maxPrefix, maxPrefix + 127,
                    maxPrefix + 128, maxPrefix + 129, 100000 }) {
                ByteBuffer buffer = ByteBuffer.allocate(16);
                PrefixedInteger.insertPrefixedInteger(prefixLength, (byte) 0, value, buffer);
                buffer.flip();
                byte[] written = new byte[buffer.remaining()];
                buffer.get(written);

                assertEquals("prefix length " + prefixLength + ", value " + value, value,
                        PrefixedInteger.parsePrefixedInteger(prefixLength, new ByteArrayInputStream(written)));
            }
        }
    }

    private static void assertRoundTrip(int prefixLength, long value) throws IOException {
        byte[] written = write(prefixLength, (byte) 0, value);

        assertEquals("prefix length " + prefixLength + ", value " + value, value,
                PrefixedInteger.parsePrefixedInteger(prefixLength, new ByteArrayInputStream(written)));
    }

    private static byte[] write(int prefixLength, byte prefixBits, long value) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        PrefixedInteger.writePrefixedInteger(prefixLength, prefixBits, value, output);
        return output.toByteArray();
    }
}
