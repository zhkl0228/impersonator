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

    /**
     * Google negotiates ALPS, so reaching it at all is the assertion. The response is a redirect to a
     * country domain, which is what this host answers a bare GET with; what matters is that there is
     * a response.
     */
    public void testAHostThatNegotiatesAlpsCompletesTheHandshake() throws Exception {
        assertEquals(302, status("https://www.google.com/"));
        assertEquals(200, status("https://www.youtube.com/"));
    }

    /**
     * The other half, and the reason this cannot be done by always sending the message: a server that
     * does not accept ALPS is not expecting it, and would answer an unrequested client
     * EncryptedExtensions the same way Google answered its absence. These three hosts do not
     * negotiate it, so they only stay reachable while the message is sent on the server's word and
     * not on the client's wish.
     */
    public void testHostsThatDoNotNegotiateAlpsAreUnaffected() throws Exception {
        assertEquals(200, status("https://nghttp2.org/"));
        assertEquals(200, status("https://cloudflare-ech.com/cdn-cgi/trace"));
        assertEquals(200, status("https://quic.tools.scrapfly.io/api/fp/quic"));
    }

    private static int status(String url) throws Exception {
        return Http3Get.status(Http3ClientFactory.create(ImpersonatorFactory.macChrome()), url);
    }
}
