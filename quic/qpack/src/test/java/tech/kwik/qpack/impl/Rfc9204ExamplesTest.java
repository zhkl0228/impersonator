package tech.kwik.qpack.impl;

import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Map;

/**
 * RFC 9204 Appendix B, decoded byte for byte.
 * <p>
 * The appendix is one exchange between an encoder and a decoder, and it is the only set of QPACK
 * vectors in existence that this project did not write itself: the hex and the field lines it decodes
 * to are the RFC's, so a disagreement here is this decoder being wrong rather than a disagreement
 * about how the RFC was read. That distinction is the reason UPSTREAM.md gives for testing the
 * dynamic table against a live server rather than against hand-written bytes - and it is exactly why
 * these bytes are worth having, because they come from the same place the server's do.
 * <p>
 * Between them the five examples reach every part of the dynamic table support that was added here:
 * all four encoder stream instructions, the field section prefix that upstream discarded, references
 * to the table both before and after the Base, eviction, and the two decoder stream instructions this
 * end sends back.
 * <p>
 * One narrative difference. In B.4 the RFC's decoder cancels stream 8 and never decodes the section;
 * this decodes it, because Stream Cancellation is the one instruction not implemented here (see
 * UPSTREAM.md) and the section's bytes are valid either way. What is asserted about it is what it
 * decodes to, which the appendix states.
 */
public class Rfc9204ExamplesTest extends TestCase {

    /**
     * The capacity the appendix's decoder must have advertised.
     * <p>
     * Not stated there, but implied: B.2's encoder sets the capacity to 220, and RFC 9204 section
     * 3.2.3 forbids setting one above the advertised maximum. It also has to be at least this for
     * B.2's Required Insert Count to resolve - it is encoded modulo twice
     * {@code floor(MaxTableCapacity / 32)}.
     */
    private static final long MAX_TABLE_CAPACITY = 220;

    private final DecoderImpl decoder = new DecoderImpl();
    private final ByteArrayOutputStream decoderStream = new ByteArrayOutputStream();

    @Override
    protected void setUp() {
        decoder.setMaxTableCapacity(MAX_TABLE_CAPACITY);
        decoder.setDecoderStream(decoderStream);
    }

    /**
     * The whole appendix in order, on one decoder, because that is what it is: each example's table
     * state is what the ones before it left behind, and decoding any of them on a fresh decoder would
     * be testing something the RFC does not describe.
     */
    public void testTheAppendixDecodesToWhatItSaysItDoes() throws Exception {
        appendixB1();
        appendixB2();
        appendixB3();
        appendixB4();
        appendixB5();
    }

    /** B.1, "Literal Field Line with Name Reference": a static name and a literal value. */
    private void appendixB1() throws Exception {
        List<Map.Entry<String, String>> fields = decodeSection(4,
                "0000" + "510b2f696e6465782e68746d6c");

        assertEquals(1, fields.size());
        assertField(":path", "/index.html", fields.get(0));
        assertEquals("no dynamic table entry was referenced, so nothing is inserted", 0,
                decoder.getDynamicTable().insertCount());
        assertEquals("and a section with Required Insert Count 0 is not acknowledged",
                "", hex(decoderStream.toByteArray()));
    }

    /**
     * B.2, "Dynamic Table": Set Dynamic Table Capacity and two Insert With Name Reference, then a
     * field section that refers to both inserts by Post-Base Index.
     */
    private void appendixB2() throws Exception {
        decodeEncoderStream("3fbd01"
                + "c00f7777772e6578616d706c652e636f6d"
                + "c10c2f73616d706c652f70617468");

        DynamicTable table = decoder.getDynamicTable();
        assertEquals("Set Dynamic Table Capacity=220", 220, table.capacity());
        assertEquals(2, table.insertCount());
        assertField(":authority", "www.example.com", table.get(0, "test"));
        assertField(":path", "/sample/path", table.get(1, "test"));
        assertEquals("the appendix says Size=106", 106, table.size());
        assertEquals("two entries arrived, so the encoder is told two did", "02", takeDecoderStream());

        List<Map.Entry<String, String>> fields = decodeSection(4, "0381" + "10" + "11");

        assertEquals(2, fields.size());
        assertField(":authority", "www.example.com", fields.get(0));
        assertField(":path", "/sample/path", fields.get(1));
        assertEquals("Section Acknowledgment (stream=4), which the appendix spells 84",
                "84", takeDecoderStream());
    }

    /** B.3, "Speculative Insert": Insert With Literal Name, and the Insert Count Increment for it. */
    private void appendixB3() throws Exception {
        decodeEncoderStream("4a637573746f6d2d6b65790c637573746f6d2d76616c7565");

        DynamicTable table = decoder.getDynamicTable();
        assertEquals(3, table.insertCount());
        assertField("custom-key", "custom-value", table.get(2, "test"));
        assertEquals("the appendix says Size=160", 160, table.size());
        assertEquals("Insert Count Increment (1), which the appendix spells 01",
                "01", takeDecoderStream());
    }

    /**
     * B.4, "Duplicate Instruction": a Duplicate by relative index, then a section referring to the
     * dynamic table below the Base and to the static table in the same breath.
     */
    private void appendixB4() throws Exception {
        decodeEncoderStream("02");

        DynamicTable table = decoder.getDynamicTable();
        assertEquals("Absolute Index = Insert Count(3) - Index(2) - 1 = 0", 4, table.insertCount());
        assertField(":authority", "www.example.com", table.get(3, "test"));
        assertEquals("the appendix says Size=217", 217, table.size());
        assertEquals("01", takeDecoderStream());

        List<Map.Entry<String, String>> fields = decodeSection(8, "0500" + "80" + "c1" + "81");

        assertEquals(3, fields.size());
        assertField("Base(4) - Index(0) - 1 = 3", ":authority", "www.example.com", fields.get(0));
        assertField("Indexed Field Line, Static Table Index = 1", ":path", "/", fields.get(1));
        assertField("Base(4) - Index(1) - 1 = 2", "custom-key", "custom-value", fields.get(2));
        assertEquals("Section Acknowledgment (stream=8)", "88", takeDecoderStream());
    }

    /**
     * B.5, "Dynamic Table Insert, Eviction": an Insert With Name Reference against the dynamic table,
     * which no longer fits and so evicts the oldest entry.
     */
    private void appendixB5() throws Exception {
        decodeEncoderStream("810d637573746f6d2d76616c756532");

        DynamicTable table = decoder.getDynamicTable();
        assertEquals(5, table.insertCount());
        assertEquals("the oldest entry was evicted to make room", 1, table.droppedCount());
        assertField("Insert Count(4) - Index(1) - 1 = 2, so the name is custom-key",
                "custom-key", "custom-value2", table.get(4, "test"));
        assertEquals("the appendix says Size=215", 215, table.size());

        try {
            table.get(0, "test");
            fail("absolute index 0 was evicted and must not resolve to whatever is at the front now");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("[1, 5)"));
        }
    }

    private List<Map.Entry<String, String>> decodeSection(long streamId, String hex) throws Exception {
        decoder.setSectionStreamId(streamId);
        return decoder.decodeStream(new ByteArrayInputStream(bytes(hex)));
    }

    private void decodeEncoderStream(String hex) throws Exception {
        decoder.decodeEncoderStream(new ByteArrayInputStream(bytes(hex)));
    }

    /** What the decoder has written back since this was last called. */
    private String takeDecoderStream() {
        String written = hex(decoderStream.toByteArray());
        decoderStream.reset();
        return written;
    }

    private static void assertField(String name, String value, Map.Entry<String, String> entry) {
        assertField("", name, value, entry);
    }

    private static void assertField(String what, String name, String value, Map.Entry<String, String> entry) {
        assertEquals(what + " name", name, entry.getKey());
        assertEquals(what + " value", value, entry.getValue());
    }

    private static byte[] bytes(String hex) {
        byte[] value = new byte[hex.length() / 2];
        for (int i = 0; i < value.length; i++) {
            value[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return value;
    }

    private static String hex(byte[] value) {
        StringBuilder text = new StringBuilder();
        for (byte b : value) {
            text.append(String.format("%02x", b));
        }
        return text.toString();
    }
}
