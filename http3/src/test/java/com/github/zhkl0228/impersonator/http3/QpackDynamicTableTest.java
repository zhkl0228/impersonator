package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.Http3Settings;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;
import tech.kwik.qpack.impl.DynamicTable;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;

/**
 * The QPACK dynamic table of RFC 9204, against a server whose encoder uses it.
 * <p>
 * Chrome's SETTINGS frame says {@code QPACK_MAX_TABLE_CAPACITY: 65536} and
 * {@code QPACK_BLOCKED_STREAMS: 100}, and those two are not descriptions of the connection - they are
 * an invitation to the peer's encoder to keep a dynamic table and to reference entries it has not
 * finished delivering. Sending them without meaning them does not cost a fingerprint, it costs the
 * connection, so what makes them sendable is a decoder that implements the table, both QPACK streams
 * and the acknowledgements; see quic/qpack/UPSTREAM.md.
 * <p>
 * Which is why this is a live test and not a set of hand-written byte vectors. Bytes made up from
 * reading the RFC would only assert that the decoder agrees with how the RFC was read. A server
 * choosing its own encoding is the thing that can disagree.
 */
public class QpackDynamicTableTest extends TestCase {

    /**
     * The one reachable server that actually encodes against the dynamic table. Cloudflare's and
     * Scrapfly's QPACK encoders set a capacity of zero and encode every field line against the static
     * table alone, so they exercise none of this - and that is most of the web, which is exactly why
     * a decoder can look fine for a long time while being wrong.
     */
    private static final String URL = "https://nghttp2.org/";

    /** Enough to get past the first response, which is where an encoder starts populating the table. */
    private static final int REQUESTS = 4;

    /**
     * That the peer inserted entries, and then referred back to them. The two are separate
     * capabilities and this is the one that matters: filling a table proves the encoder stream was
     * read, while referring to it proves the indexing, the Base and the acknowledgements are right -
     * a server only keeps referencing entries it has been told arrived.
     */
    public void testTheDynamicTableIsReallyUsed() throws Exception {
        try (Http3Client client = get(REQUESTS)) {
            Http3Connection connection = connectionOf(client);
            DynamicTable table = connection.dynamicTable();

            assertTrue("the peer set no dynamic table capacity, so nothing here was exercised",
                    table.capacity() > 0);
            assertTrue("the peer inserted nothing into the dynamic table", table.insertCount() > 0);
            assertTrue("the peer inserted " + table.insertCount() + " entries but referred to none of them,"
                            + " so no field line was decoded through the dynamic table",
                    connection.dynamicTableReferences() > 0);
        }
    }

    /**
     * That what came back through those references is right. An off-by-one in the absolute index, the
     * Base or the eviction count does not throw - it returns a neighbouring entry - so the check has
     * to be on the field lines themselves, and the response is the only place they can be seen.
     */
    public void testTheHeadersDecodedThroughItAreRight() throws Exception {
        try (Http3Client client = get(REQUESTS - 1)) {
            HttpResponse<String> response = send(client);
            assertTrue("nothing was decoded through the dynamic table, so this asserts nothing",
                    connectionOf(client).dynamicTableReferences() > 0);

            assertEquals(200, response.statusCode());
            Optional<String> contentType = response.headers().firstValue("content-type");
            assertTrue("no content-type came back at all", contentType.isPresent());
            assertTrue("content-type decoded as " + contentType.get(), contentType.get().startsWith("text/html"));
            assertTrue("no date header came back", response.headers().firstValue("date").isPresent());
        }
    }

    /**
     * That the two numbers in the SETTINGS frame are the two numbers the decoder was built with.
     * They are written in a profile and honoured somewhere else entirely, so nothing but this stops
     * the frame and the implementation drifting apart - and the drift would show up as a peer taking
     * a liberty this end had stopped allowing.
     */
    public void testWhatIsAdvertisedIsWhatTheDecoderWasGiven() throws Exception {
        try (Http3Client client = get(1)) {
            Http3Connection connection = connectionOf(client);

            assertEquals(0x10000L, connection.advertised(Http3Settings.QPACK_MAX_TABLE_CAPACITY));
            assertEquals(100L, connection.advertised(Http3Settings.QPACK_BLOCKED_STREAMS));

            assertEquals("the frame promises a dynamic table the decoder was not given",
                    connection.advertised(Http3Settings.QPACK_MAX_TABLE_CAPACITY),
                    connection.dynamicTable().maxCapacity());
            assertEquals("the frame promises blocked streams the decoder was not given",
                    connection.advertised(Http3Settings.QPACK_BLOCKED_STREAMS),
                    connection.qpackMaxBlockedStreams());
        }
    }

    private static Http3Client get(int requests) throws Exception {
        Http3Client client = (Http3Client) Http3ClientFactory.create(ImpersonatorFactory.macChrome()).newHttpClient();
        try {
            for (int i = 0; i < requests; i++) {
                assertEquals(200, send(client).statusCode());
            }
        }
        catch (Exception e) {
            client.close();
            throw e;
        }
        return client;
    }

    private static HttpResponse<String> send(Http3Client client) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(URL)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static Http3Connection connectionOf(Http3Client client) {
        URI uri = URI.create(URL);
        Http3Connection connection = client.openConnection(uri.getHost() + ":443");
        assertNotNull("no connection to " + uri.getHost() + " is open", connection);
        return connection;
    }
}
