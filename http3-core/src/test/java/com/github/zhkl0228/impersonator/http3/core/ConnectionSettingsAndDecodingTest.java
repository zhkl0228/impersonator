package com.github.zhkl0228.impersonator.http3.core;

import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import junit.framework.TestCase;
import tech.kwik.flupke.impl.HeadersFrame;
import tech.kwik.qpack.Decoder;
import tech.kwik.qpack.Encoder;
import tech.kwik.qpack.impl.HttpQPackDecompressionFailedException;

import java.io.ByteArrayInputStream;
import java.net.ConnectException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * The two things a caller needs when it drives the QUIC connection itself rather than only sending
 * requests: settings this factory has no opinion about, and the connection's own QPACK decoder.
 * <p>
 * Both come from using an HTTP/3 connection as one stream among several - a proxy protocol that
 * authenticates over HTTP/3 and then relays on streams of its own. Such a caller needs a certificate
 * check it turns off itself, an address to dial that is not the name it sends, an idle timeout, and
 * the datagram extension; and it reads HEADERS off streams this class knows nothing about.
 */
public class ConnectionSettingsAndDecodingTest extends TestCase {

    private static final String URL = "https://gzmtx.cn:8444/connection-settings";

    /**
     * The caller's settings reach the builder, and reach it last.
     * <p>
     * Asserted through the one setting whose effect is unmistakable: a connect timeout no handshake
     * can meet. It is also one this factory sets itself, so a failure here says both that the
     * caller's settings are applied and that they are applied after - which is the documented order,
     * and the only one that lets a caller change its mind about something with a default.
     */
    public void testTheCallersSettingsAreAppliedAndAreAppliedLast() throws Exception {
        Http3ConnectionFactory factory = Http3ConnectionFactory.create(ImpersonatorFactory.macChrome());
        factory.setConnectTimeout(Duration.ofSeconds(10));

        try {
            factory.newConnection(URI.create(URL), builder -> builder.connectTimeout(Duration.ofMillis(1)));
            fail("a one millisecond connect timeout was not applied, or was applied before the"
                    + " factory's own ten seconds");
        }
        catch (ConnectException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("1 ms"));
        }
    }

    /**
     * And a connection made with settings of the caller's is still the browser's connection: the
     * builder handed over is one this factory made, with the profile already on it.
     */
    public void testASettingOfTheCallersDoesNotCostTheProfile() throws Exception {
        Http3ConnectionFactory factory = Http3ConnectionFactory.create(ImpersonatorFactory.macChrome());

        try (Http3Connection connection = factory.newConnection(URI.create(URL),
                builder -> builder.maxIdleTimeout(Duration.ofSeconds(30)).enableDatagramExtension())) {
            assertEquals("the SETTINGS frame is still Chrome's", 65536,
                    connection.advertised(1));   // SETTINGS_QPACK_MAX_TABLE_CAPACITY
            assertTrue("the connection did not come up", connection.getQuicConnection().isConnected());
        }
    }

    /**
     * A field section decoded through the connection comes back as what was encoded.
     * <p>
     * Encoded here with qpack's own encoder, which uses the static table and literals and never the
     * dynamic table - so this is the half that a throwaway decoder would also get right. What it
     * checks is the plumbing: that the bytes reach a decoder at all and that the stream id is
     * accepted.
     */
    public void testAFieldSectionDecodesToWhatWasEncoded() throws Exception {
        Http3ConnectionFactory factory = Http3ConnectionFactory.create(ImpersonatorFactory.macChrome());

        try (Http3Connection connection = factory.newConnection(URI.create(URL))) {
            List<Map.Entry<String, String>> fields = Arrays.asList(
                    field(":status", "200"),
                    field("content-type", "application/json"),
                    field("x-relay", "hello"));
            HeadersFrame decoded = connection.parseHeaders(0, encoded(fields));

            assertEquals("200", decoded.getPseudoHeader(":status"));
            assertEquals("application/json",
                    decoded.headers().firstValue("content-type").orElse(null));
            assertEquals("hello", decoded.headers().firstValue("x-relay").orElse(null));
        }
    }

    /**
     * And it is the connection's decoder, not a fresh one.
     * <p>
     * The two answer differently to the same bytes, which is the whole reason this method exists. A
     * field section prefix that names a Required Insert Count is decoded against the number of entries
     * the decoder's table can hold: this connection advertised 65536 bytes, so it works out what the
     * count resolves to and says that this one resolves to zero - which RFC 9204 section 4.5.1.1 only
     * encodes as zero. A decoder that was never told about a table gets no further than saying it has
     * none. Same bytes, two decoders, two reasons.
     * <p>
     * The section that follows the prefix is never reached, so it is not written here: what is being
     * told apart is the two decoders, not the two sections.
     */
    public void testItIsTheConnectionsDecoderAndNotAFreshOne() throws Exception {
        Http3ConnectionFactory factory = Http3ConnectionFactory.create(ImpersonatorFactory.macChrome());
        byte[] section = { 0x01, 0x00 };   // Required Insert Count 1, Base 0, then nothing

        try (Http3Connection connection = factory.newConnection(URI.create(URL))) {
            String throughTheConnection = refusalOf(() -> connection.parseHeaders(0, section));
            String throughAFreshDecoder = refusalOf(() ->
                    new HeadersFrame().parsePayload(section, Decoder.newBuilder().build()));

            assertTrue("a decoder with no table cannot say more than that: " + throughAFreshDecoder,
                    throughAFreshDecoder.contains("advertised no dynamic table capacity"));
            assertFalse("the connection's decoder has one, and this says it does not: "
                    + throughTheConnection,
                    throughTheConnection.contains("advertised no dynamic table capacity"));
            assertTrue("it resolved the count against its own table instead: " + throughTheConnection,
                    throughTheConnection.contains("resolves to zero"));
        }
    }

    private interface Decoding {
        void run() throws Exception;
    }

    /** What a decoder said when it refused; fails the test if it did not refuse. */
    private static String refusalOf(Decoding decoding) throws Exception {
        try {
            decoding.run();
            fail("a field section that names a dynamic table entry this end has not been sent must"
                    + " not decode to anything");
            return null;
        }
        catch (HttpQPackDecompressionFailedException refused) {
            return String.valueOf(refused.getMessage());
        }
    }

    private static byte[] encoded(List<Map.Entry<String, String>> fields) {
        ByteBuffer buffer = Encoder.newBuilder().build().compressHeaders(fields);
        ByteBuffer written = buffer.duplicate();
        written.flip();
        byte[] bytes = new byte[written.remaining()];
        written.get(bytes);
        return bytes;
    }

    private static Map.Entry<String, String> field(String name, String value) {
        return new AbstractMap.SimpleEntry<>(name, value);
    }
}
