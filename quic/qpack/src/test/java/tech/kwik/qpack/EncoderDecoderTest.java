package tech.kwik.qpack;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;

/**
 * A field section through the public API: encoded by the encoder, decoded by the decoder.
 * <p>
 * Not the circular test it looks like. The encoder here is qpack's own, and the two things this
 * project changed in it - see UPSTREAM.md, where the deviations are listed - leave the encoding
 * upstream's: three copies of the same string literal writer folded into one, which writes the byte
 * for byte same section, and a rule about when Huffman coding is worth taking, which decides between
 * two encodings upstream already had. So what this compares is a modified decoder against an
 * encoding this project did not invent. That is a real check of the paths a field section takes when
 * there is no dynamic table: the static table, both kinds of literal, Huffman, and the section
 * prefix, which upstream's decoder read past without parsing and this one parses.
 * <p>
 * The dynamic table cannot be reached this way, because this encoder has none to fill. It is covered
 * by {@link tech.kwik.qpack.impl.Rfc9204ExamplesTest} against the RFC's own bytes and by
 * {@code QpackDynamicTableTest} in impersonator-http3 against a server that really uses one.
 */
public class EncoderDecoderTest extends TestCase {

    /** A field line that is in the static table whole, so it goes out as a single index byte. */
    public void testAFieldLineTheStaticTableHasWholeSurvives() throws Exception {
        assertRoundTrip(field(":method", "GET"));
        assertRoundTrip(field(":scheme", "https"));
        assertRoundTrip(field(":path", "/"));
    }

    /** A name the static table has with a different value: an index for the name, a literal value. */
    public void testAStaticNameWithItsOwnValueSurvives() throws Exception {
        assertRoundTrip(field(":path", "/index.html"));
        assertRoundTrip(field(":authority", "www.example.com"));
    }

    /** And a field line the static table has never heard of, name and value both literal. */
    public void testAFieldLineTheStaticTableDoesNotHaveSurvives() throws Exception {
        assertRoundTrip(field("x-custom-header", "custom value"));
    }

    /**
     * The whole section, in order. QPACK is free to encode each line differently and the decoder has
     * to put them back in the order they were written, which is what an HTTP/3 request depends on -
     * and what this project's own field ordering is about.
     */
    public void testAWholeRequestSurvivesInOrder() throws Exception {
        assertRoundTrip(
                field(":method", "GET"),
                field(":authority", "www.example.com"),
                field(":scheme", "https"),
                field(":path", "/index.html"),
                field("user-agent", "Mozilla/5.0"),
                field("accept", "text/html,application/xhtml+xml"));
    }

    /**
     * With Huffman coding, which is off by default in this encoder and on in every browser's. It is
     * the same field lines and a different string encoding, so the decoder has to answer the same
     * thing to both.
     */
    public void testHuffmanCodedStringsDecodeToTheSameFieldLines() throws Exception {
        List<Map.Entry<String, String>> fields = Arrays.asList(
                field(":method", "GET"),
                field(":path", "/some/rather/long/path?with=a&query=string"),
                field("x-custom-header", "a value long enough for Huffman to be worth it"));

        assertEquals(fields, decode(encode(true, fields)));
        assertFalse("and the two encodings are not the same bytes, or this asserts nothing", Arrays.equals(bytes(encode(true, fields)), bytes(encode(false, fields))));
    }

    /**
     * A value long enough that its length does not fit the 7 bit prefix, which is where the prefixed
     * integer's continuation bytes come in - the part two bugs were found in; see
     * {@link tech.kwik.qpack.impl.PrefixedIntegerTest}.
     */
    public void testAValueTooLongForTheLengthPrefixSurvives() throws Exception {
        StringBuilder value = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            value.append((char) ('a' + i % 26));
        }
        assertRoundTrip(field("x-long-header", value.toString()));
    }

    /**
     * A value whose Huffman coded form is longer than the value. RFC 7541 appendix B spends 12 to 15
     * bits on '#', '$', '@', '[', ']', '^', '{' and '}', and an encoder that took the coded form
     * whatever it cost wrote past the buffer it had sized from the plain lengths - a
     * BufferOverflowException out of compressHeaders, for a field line that is perfectly legal.
     */
    public void testAValueHuffmanCodingWouldLengthenGoesOutUncoded() throws Exception {
        StringBuilder value = new StringBuilder();
        value.append("\\^{}@[]#$~'".repeat(20));
        Map.Entry<String, String> field = field("cookie", value.toString());

        assertTrue("the premise: Huffman does lengthen this value",
                huffmanCodedLength(value.toString()) > value.length());
        assertRoundTrip(field);
        assertArrayEquals("so asking for Huffman has to leave it uncoded, byte for byte the plain encoding", bytes(encode(true, List.of(field))), bytes(encode(false, List.of(field))));
    }

    private static int huffmanCodedLength(String value) {
        return tech.kwik.qpack.impl.Huffman.getInstance()
                .encode(value.getBytes(tech.kwik.qpack.impl.EncoderImpl.HTTP_HEADER_CHARSET)).length;
    }

    /** An empty value is a field line all the same, and its length prefix is the interesting part. */
    public void testAnEmptyValueSurvives() throws Exception {
        assertRoundTrip(field("x-empty", ""));
    }

    /**
     * Huffman coding an empty string, or a one character value, saves nothing: both code to the same
     * number of bytes they already take. A tie is not a win, so those go out plain - the H bit says
     * what was done, and setting it over no bytes at all says something that was not.
     * <p>
     * The name is `cookie` because the static table has it with an empty value: the field line is then
     * an index for the name and a literal for the value, so the value is the only string in the
     * section and the two encodings can be compared whole.
     */
    public void testAStringHuffmanCodingWouldNotShortenGoesOutUncoded() throws Exception {
        for (Map.Entry<String, String> field : Arrays.asList(field("cookie", ""), field("cookie", "v"))) {
            assertArrayEquals("value \"" + field.getValue() + "\" is coded where coding it gains nothing", bytes(encode(true, List.of(field))), bytes(encode(false, List.of(field))));
            assertRoundTrip(field);
        }
    }

    @SafeVarargs
    private static void assertRoundTrip(Map.Entry<String, String>... fields) throws Exception {
        List<Map.Entry<String, String>> section = Arrays.asList(fields);

        assertEquals(section, decode(encode(false, section)));
        assertEquals(section, decode(encode(true, section)));
    }

    private static ByteBuffer encode(boolean huffman, List<Map.Entry<String, String>> fields) {
        return Encoder.newBuilder().useHuffmanEncoding(huffman).build().compressHeaders(fields);
    }

    private static List<Map.Entry<String, String>> decode(ByteBuffer encoded) throws Exception {
        return new ArrayList<>(Decoder.newBuilder().build()
                .decodeStream(new ByteArrayInputStream(bytes(encoded))));
    }

    /** The encoder leaves its buffer at the end of what it wrote, as its own javadoc says. */
    private static byte[] bytes(ByteBuffer buffer) {
        ByteBuffer written = buffer.duplicate();
        written.flip();
        byte[] value = new byte[written.remaining()];
        written.get(value);
        return value;
    }

    private static Map.Entry<String, String> field(String name, String value) {
        return new AbstractMap.SimpleEntry<>(name, value);
    }
}
