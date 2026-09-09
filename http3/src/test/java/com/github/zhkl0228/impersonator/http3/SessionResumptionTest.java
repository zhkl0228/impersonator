package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;
import tech.kwik.core.impl.QuicClientConnectionImpl;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Session resumption and 0-RTT, which is a fingerprint matter before it is a performance one.
 * <p>
 * A browser resumes. After the first visit its ClientHello to a host carries a "pre_shared_key" and
 * an "early_data", and it is a different message with a different JA4: Chrome's fresh QUIC
 * ClientHello has twelve extensions and its resumed one has fourteen. A client that never resumes
 * sends the same full handshake to the same host for ever, which is not so much a wrong fingerprint
 * as an impossible history - no browser has visited a site a hundred times without once presenting a
 * ticket. Both of Chrome's are captured in docs/captures, and both are what this asserts.
 * <p>
 * Half of this would have been worse than none. Offering the pre_shared_key without the early_data
 * gives a thirteen extension ClientHello and a JA4 no Chrome has ever sent, which is why 0-RTT is
 * here too rather than left for later.
 */
public class SessionResumptionTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** From docs/captures/chrome-152-quic.json - Chrome's first connection to a host. */
    private static final String CHROME_FRESH_JA4 = "q13d0312h3_55b375c5d22e_54c9dd0422dd";

    /** From docs/captures/chrome-152-quic-resumed.json - Chrome's ClientHello after a refresh. */
    private static final String CHROME_RESUMED_JA4 = "q13d0314h3_55b375c5d22e_22df90fcce4c";

    /**
     * The whole point in one: the first connection is Chrome's full handshake and every one after it
     * is Chrome's resumed handshake, both matched against the captures. The tickets come from the
     * factory, which is the scope a browser's ticket cache has - one profile, every host it visited.
     */
    public void testTheFirstConnectionIsFreshAndTheRestResume() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome());

        assertEquals("the first connection has no ticket to offer", CHROME_FRESH_JA4, ja4(factory));
        assertEquals(CHROME_RESUMED_JA4, ja4(factory));
        assertEquals("a ticket is used once, so the third connection needs one of its own",
                CHROME_RESUMED_JA4, ja4(factory));
    }

    /**
     * That the "early_data" in that ClientHello is meant. The client writes its HTTP/3 control stream
     * and SETTINGS in 0-RTT packets, which is what an HTTP/3 connection has to say first and the only
     * thing it can say before the handshake finishes.
     * <p>
     * Whether the server then <em>accepts</em> the early data is the server's own decision - it may
     * refuse for replay reasons and often does, in which case kwik sends the same bytes again once
     * the handshake completes - so what is asserted here is the half this end controls: that early
     * data was requested and written. Offering the extension and writing nothing would be the same
     * mistake as advertising a QPACK dynamic table with no decoder behind it.
     */
    public void testTheResumedConnectionReallyWritesEarlyData() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome());
        get(factory);

        try (Http3Client client = (Http3Client) factory.newHttpClient()) {
            URI uri = URI.create(FINGERPRINT_URL);
            client.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.discarding());

            QuicClientConnectionImpl connection =
                    (QuicClientConnectionImpl) client.quicConnectionFor(uri.getHost() + ":443");
            assertNotNull("no connection to " + uri.getHost() + " is open", connection);
            assertTrue("the resumed connection wrote no early data, so its \"early_data\" was a claim"
                            + " about this client that is not true",
                    connection.getEarlyDataStatus() != QuicClientConnectionImpl.EarlyDataStatus.None);
        }
    }

    /**
     * A host that publishes an ECHConfig keeps its Encrypted Client Hello and does not resume.
     * <p>
     * The two cannot both be used: RFC 9849 has the ClientHelloInner and the ClientHelloOuter carry
     * different pre_shared_key extensions, the outer's a GREASE one, and there is no capture of what
     * a browser puts in the outer - so it is not implemented and not guessed at. ECH wins, because it
     * hides the server name from everyone on the path while resumption only saves a round trip and
     * makes the ClientHello look like a second visit. Giving up the name for that would be the wrong
     * way round, and the choice is asserted here rather than left to be discovered.
     */
    public void testAnEchHostKeepsItsEncryptedClientHelloInsteadOfResuming() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome())
                .setEchConfigProvider(com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider.getInstance());
        String url = "https://cloudflare-ech.com/cdn-cgi/trace";

        assertTrue("the first connection should encrypt the server name",
                Http3Get.body(factory, url).contains("sni=encrypted"));
        assertTrue("the second connection must not trade the encrypted server name for a resumption",
                Http3Get.body(factory, url).contains("sni=encrypted"));
    }

    private static String ja4(Http3ClientFactory factory) throws Exception {
        return get(factory).getString("ja4");
    }

    private static JSONObject get(Http3ClientFactory factory) throws Exception {
        String body = Http3Get.body(factory, FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
        return fingerprint;
    }
}
