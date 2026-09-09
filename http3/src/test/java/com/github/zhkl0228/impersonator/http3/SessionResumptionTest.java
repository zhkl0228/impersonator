package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider;
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
     * Whether a ticket is <em>accepted</em> has to be asked of a server that reliably accepts one.
     * The fingerprinting endpoint above is not that server: it answers a ticket it issued itself with
     * a full handshake about as often as not, which is what a host behind several backends without a
     * shared ticket key looks like, and it flip-flops on 0-RTT the same way. It is still the right
     * place to ask what the ClientHello <em>looks</em> like, which is settled by this end alone.
     */
    private static final String ACCEPTING_URL = "https://www.google.com/";

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
     * That the resumption is real and not a costume. This is the assertion that matters most here,
     * because its absence is invisible: a server that will not accept the ticket - because the binder
     * was computed over the wrong bytes, say - simply does a full handshake instead, and the
     * ClientHello that offered it is identical on the wire either way. An earlier version of this
     * work produced exactly the right resumed JA4 while every connection was in fact a full
     * handshake, and only the ServerHello's pre_shared_key told the difference.
     */
    public void testTheServerReallyAcceptsTheTicket() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome());
        assertFalse("the first connection has no ticket, so nothing to accept", resumed(factory, ACCEPTING_URL));

        assertTrue("the ClientHello offered a pre_shared_key and the server did not answer with one,"
                + " so this connection only looks resumed", resumed(factory, ACCEPTING_URL));
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
     * A host that publishes an ECHConfig gets both: the server name stays encrypted and the session
     * still resumes.
     * <p>
     * These were refused together for a while, on the grounds that the two ClientHellos would need
     * their own binders over their own transcripts. They do not. The ClientHelloOuter carries no
     * pre_shared_key at all - RFC 9849 section 6.1.2 recommends a GREASE one and BoringSSL declines,
     * its should_offer_psk returning false for the outer outright - so there is one binder and it
     * covers the ClientHelloInner, which is also the transcript and the one the 0-RTT keys come from.
     * <p>
     * Refusing was the expensive choice, and it was made for a bad reason: it meant every
     * Cloudflare-fronted host, which is where ECH is actually deployed, could never resume.
     */
    public void testAnEchHostResumesWithoutGivingUpTheEncryptedServerName() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macChrome())
                .setEchConfigProvider(DnsOverHttpsEchConfigProvider.getInstance());
        String url = "https://cloudflare-ech.com/cdn-cgi/trace";

        assertTrue("the first connection should encrypt the server name",
                Http3Get.body(factory, url).contains("sni=encrypted"));

        try (Http3Client client = (Http3Client) factory.newHttpClient()) {
            String body = client.send(HttpRequest.newBuilder(URI.create(url)).build(),
                    HttpResponse.BodyHandlers.ofString()).body();
            assertTrue("the second connection must keep the encrypted server name", body.contains("sni=encrypted"));
            assertTrue("and must resume, rather than trading one for the other",
                    client.quicConnectionFor("cloudflare-ech.com:443").isSessionResumed());
        }
    }

    private static boolean resumed(Http3ClientFactory factory, String url) throws Exception {
        URI uri = URI.create(url);
        try (Http3Client client = (Http3Client) factory.newHttpClient()) {
            client.send(HttpRequest.newBuilder(uri).build(), HttpResponse.BodyHandlers.ofString());
            return client.quicConnectionFor(uri.getHost() + ":443").isSessionResumed();
        }
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
