package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import junit.framework.TestCase;
import tech.kwik.core.impl.QuicClientConnectionImpl;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;

/**
 * Address validation for future connections: the token a server hands out in a NEW_TOKEN frame, kept
 * and sent in the Initial packets of the next connection to that host.
 * <p>
 * A fingerprint matter of the same kind as never resuming. RFC 9000 section 8.1.3 says the client
 * "MUST include the token in all Initial packets it sends", and a server that has not validated an
 * address may answer with a Retry - so a client that keeps no token pays a round trip on every
 * connection where a browser pays it once, and its Initial packets have an empty token field for
 * ever. Both are visible in the first datagram. kwik received these frames and dropped them.
 * <p>
 * What a server does with the token was checked against ngtcp2's own server, run with address
 * validation forced on (docs/tools/README.md has the recipe). Its log for three connections in a
 * row, the first with nothing to show and the two after it carrying what it had issued:
 * <pre>
 *   Sending Retry packet to [..]:20681      &lt;- first connection, no token
 *   Verifying Retry token from [..]:20681
 *   Token was successfully validated
 *   Verifying token from [..]:20683         &lt;- second connection, NEW_TOKEN token, no Retry
 *   Token was successfully validated
 *   Verifying token from [..]:20686         &lt;- third
 *   Token was successfully validated
 * </pre>
 * "Verifying token" rather than "Verifying Retry token" is the server saying which of the two kinds
 * it got, and no Retry follows either of them: the round trip is gone, which is the whole point.
 */
public class AddressValidationTest extends TestCase {

    /**
     * A host that issues one. Not every server does - Cloudflare's QUIC endpoint issues none at all,
     * which is its right and costs its clients nothing but a possible Retry.
     */
    private static final String ISSUING_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /**
     * As long as {@link Http3Get} waits, and for the same reason: a NEW_TOKEN frame is not tied to
     * the response either, so this waits for the token itself rather than for a length of time.
     */
    private static final long MAX_SETTLE_MILLIS = 2000;

    /**
     * The first connection is given a token and the second one sends it.
     * <p>
     * The second half is what matters and is easy to get wrong invisibly: keeping the token and never
     * putting it in the Initial packet looks exactly like this from the outside, the connection
     * succeeding either way. So this asks the connection itself what it is carrying.
     */
    public void testTheSecondConnectionCarriesTheTokenTheFirstWasGiven() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome());

        byte[] issued = tokenFrom(factory);
        assertNotNull("this endpoint issues a NEW_TOKEN and the connection kept none", issued);

        byte[] carried = initialTokenOf(factory);
        assertNotNull("the second connection sent an Initial packet with an empty token field", carried);
        assertTrue("the token sent is not the one that was issued: " + Arrays.toString(carried),
                Arrays.equals(issued, carried));
    }

    /**
     * A token is used once - "Reusing a token allows connections to be linked by entities on the
     * network path" - so the third connection needs one of its own, and gets it because every
     * connection is issued a new one.
     */
    public void testEveryConnectionCarriesADifferentToken() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome());
        tokenFrom(factory);

        byte[] second = initialTokenOf(factory);
        byte[] third = initialTokenOf(factory);

        assertNotNull(second);
        assertNotNull("the third connection had nothing to send, so the second kept nothing", third);
        assertFalse("the same token twice is the linkability RFC 9000 8.1.3 asks a client to avoid",
                Arrays.equals(second, third));
    }

    private static String authority() {
        return Http3Get.authorityOf(ISSUING_URL);
    }

    /** Waits for the connection's NEW_TOKEN frame, which can come after the response it follows. */
    private static List<byte[]> awaitToken(Http3Client client) throws InterruptedException {
        List<byte[]> tokens = client.quicConnectionFor(authority()).getNewTokens();
        long deadline = System.currentTimeMillis() + MAX_SETTLE_MILLIS;
        while (tokens.isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        return tokens;
    }

    /** The tokens the connection to the endpoint was given. */
    private static byte[] tokenFrom(Http3ClientFactory factory) throws Exception {
        try (Http3Client client = (Http3Client) factory.newHttpClient()) {
            client.send(HttpRequest.newBuilder(URI.create(ISSUING_URL)).build(),
                    HttpResponse.BodyHandlers.discarding());
            List<byte[]> tokens = awaitToken(client);
            return tokens.isEmpty() ? null : tokens.get(tokens.size() - 1);
        }
    }

    /**
     * What the connection put in its Initial packets. Equal to what it was built with unless a Retry
     * replaced it, which is what {@link QuicClientConnectionImpl#getInitialToken()} says.
     */
    private static byte[] initialTokenOf(Http3ClientFactory factory) throws Exception {
        try (Http3Client client = (Http3Client) factory.newHttpClient()) {
            client.send(HttpRequest.newBuilder(URI.create(ISSUING_URL)).build(),
                    HttpResponse.BodyHandlers.discarding());
            // Waited for here too, so that the connection after this one has a token of its own.
            awaitToken(client);
            QuicClientConnectionImpl connection =
                    (QuicClientConnectionImpl) client.quicConnectionFor(authority());
            return connection.getInitialToken();
        }
    }
}
