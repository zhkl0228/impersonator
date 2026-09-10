package tech.kwik.qpack.impl;

import junit.framework.TestCase;

import java.util.Base64;

/**
 * The Huffman code of RFC 7541 appendix B, and the two things this project changed about it.
 * <p>
 * Both were found by asking a field section with an empty value to survive being encoded and decoded,
 * which it did not: it came back as {@code x-empty=0a}, two characters nobody wrote. One end of that
 * was an encoder writing a byte it had no bits for, the other a decoder turning that byte into
 * symbols instead of refusing it, and either alone would have hidden the other.
 */
public class HuffmanTest extends TestCase {

    private final Huffman huffman = Huffman.getInstance();

    /**
     * An empty string is zero bytes. The length calculation read {@code (0 - 1) / 8 + 1}, which is 1
     * in Java, so an empty value went out as a one byte string holding 0x00 - a byte that encodes
     * nothing, since the padding that would have filled it is only written when there are bits to pad.
     */
    public void testAnEmptyStringEncodesToNoBytes() {
        assertEquals(0, huffman.encode("").length);
    }

    /**
     * RFC 7541 section 5.2: "A padding not corresponding to the most significant bits of the code for
     * the EOS symbol MUST be treated as a decoding error." The EOS code is all ones, so a final byte
     * of 0x00 is not padding at all.
     * <p>
     * It used to decode. The lookup consumed whatever was left with a comment guessing it was
     * "probably just 1's" and returned nothing, after which the zero bits before it had already been
     * read as symbols - which is how one byte of nothing became "0a". A header field invented out of
     * padding is worse than a failed request, because nothing downstream can tell it was invented.
     */
    public void testPaddingThatIsNotTheEosPrefixIsRefused() {
        try {
            huffman.decode(new byte[] { 0x00 });
            fail("0x00 is not the EOS padding RFC 7541 requires and must not decode to anything");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertTrue("the message must name the rule and carry the bytes: " + expected.getMessage(),
                    expected.getMessage().contains("RFC 7541")
                            && expected.getMessage().contains(Base64.getEncoder().encodeToString(new byte[] { 0 })));
        }
    }

    /** And the padding that is the EOS prefix still decodes, which is most of the traffic there is. */
    public void testAStringWrittenComesBackAsItself() {
        String[] values = { "a", "x-empty", "/index.html", "www.example.com", "custom-value",
                "text/html,application/xhtml+xml;q=0.9", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "0123456789", "" };
        for (String value : values) {
            assertEquals(value, huffman.decode(huffman.encode(value)));
        }
    }

    /**
     * A string whose codes happen to end on a byte boundary has no padding at all, which is the case
     * the strictness must not reject. "a" is five bits and "0" is five bits, so eight of them are
     * forty bits: five whole bytes.
     */
    public void testAStringThatNeedsNoPaddingIsNotRejected() {
        String value = "a0a0a0a0";

        assertEquals(5, huffman.encode(value).length);
        assertEquals(value, huffman.decode(huffman.encode(value)));
    }
}
