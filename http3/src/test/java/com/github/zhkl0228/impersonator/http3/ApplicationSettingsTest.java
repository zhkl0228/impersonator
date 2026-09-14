package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;

/**
 * Application-Layer Protocol Settings (draft-vvv-tls-alps), which the Chrome profile advertises and
 * therefore has to finish.
 * <p>
 * ALPS is not an extension the server may quietly ignore. A server that accepts it - by echoing
 * "application_settings" in its EncryptedExtensions - then waits for the client's own
 * EncryptedExtensions before the Finished, and TLS 1.3 otherwise never has the client send handshake
 * type 8 at all. Until that message was sent, Google answered the Finished that arrived in its place
 * with {@code UNEXPECTED_MESSAGE (got type 20, wanted type 8)} and closed the connection, so the
 * profile could not reach Google over HTTP/3 no matter what else was right.
 * <p>
 * Which makes this a test about a whole class of mistake rather than about one host: an extension
 * copied out of a capture for the sake of the fingerprint can carry an obligation with it, and the
 * bytes of the ClientHello look exactly the same either way.
 */
public class ApplicationSettingsTest extends TestCase {

    /** Google negotiates ALPS, so reaching it at all is the assertion. */
    public void testAHostThatNegotiatesAlpsCompletesTheHandshake() throws Exception {
        assertAnswered("https://www.google.com/");
        assertAnswered("https://www.youtube.com/");
    }

    /**
     * The other half, and the reason this cannot be done by always sending the message: a server that
     * does not accept ALPS is not expecting it, and would answer an unrequested client
     * EncryptedExtensions the same way Google answered its absence. These three hosts do not
     * negotiate it, so they only stay reachable while the message is sent on the server's word and
     * not on the client's wish.
     */
    public void testHostsThatDoNotNegotiateAlpsAreUnaffected() throws Exception {
        /*
         * Two hosts and not three. nghttp2.org was here as well and times out often enough to fail
         * this run about once in three, and what it was proving - that a server which does not
         * negotiate ALPS still works - either of these proves as well. It is kept in
         * QpackDynamicTableTest, which has no substitute for it: it is the only reachable server
         * whose QPACK encoder uses the dynamic table at all.
         */
        assertEquals(200, status("https://cloudflare-ech.com/cdn-cgi/trace"));
        assertEquals(200, status("https://quic.tools.scrapfly.io/api/fp/quic"));
    }

    /**
     * That the host answered at all, which is the whole of what ALPS decides. A handshake it broke
     * never gets this far: the server closes the connection and {@link Http3Get#status} throws rather
     * than returning a number, so a number returned is the pass.
     * <p>
     * Which number it is belongs to the host and not to this test. www.google.com answered a bare GET
     * with 302 to a country domain when this was written and answers 200 now - a redirect policy that
     * says nothing about ALPS - and the assertion that pinned 302 failed for it. The range is here so
     * that a 4xx or 5xx, which would be the host refusing rather than serving, still does not pass.
     */
    private static void assertAnswered(String url) throws Exception {
        int status = status(url);
        assertTrue(url + " answered " + status + " rather than serving the GET", status >= 200 && status < 400);
    }

    private static int status(String url) throws Exception {
        return Http3Get.status(Http3ClientFactory.create(ImpersonatorFactory.macChrome()), url);
    }
}
