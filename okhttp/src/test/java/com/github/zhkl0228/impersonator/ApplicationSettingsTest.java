package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Application-Layer Protocol Settings (draft-vvv-tls-alps) on the TCP path, and the HTTP/2 header
 * table that goes with it.
 * <p>
 * The Chrome profile advertises "application_settings", and that is not an extension a server may
 * quietly ignore: one that accepts it - by echoing the extension in its EncryptedExtensions - then
 * waits for the client's own EncryptedExtensions before the Finished, which is the one place in TLS
 * 1.3 where handshake type 8 travels from client to server. Until it was sent, Google answered the
 * Finished that arrived in its place with {@code unexpected_message} and dropped the connection.
 * <p>
 * Getting past that uncovered the same mistake one layer up. The profile announces
 * {@code SETTINGS_HEADER_TABLE_SIZE: 65536}, which is permission for the peer's HPACK encoder to use
 * a table that big, and okhttp's decoder still believed its own 4096 - so Google's first dynamic
 * table size update was rejected as invalid. Both are the same error: a value copied from a capture
 * for the sake of the fingerprint is a promise about this end, and the bytes look identical whether
 * or not it is kept.
 */
public class ApplicationSettingsTest extends TestCase {

    /**
     * Google negotiates ALPS and takes the header table up on its offer, so simply getting a
     * response is the assertion; both of these fail at the TLS handshake without the client
     * EncryptedExtensions, and at the first header block without the table size.
     */
    public void testHostsThatNegotiateAlpsAndUseTheHeaderTable() throws Exception {
        assertEquals(200, status("https://www.google.com/"));
        assertEquals(200, status("https://www.youtube.com/"));
    }

    /**
     * The other half: a server that does not accept ALPS is not expecting the client's
     * EncryptedExtensions and would reject it exactly as Google rejected its absence. These stay
     * reachable only while the message is sent on the server's word rather than on the client's.
     */
    public void testHostsThatDoNotNegotiateAlpsAreUnaffected() throws Exception {
        assertEquals(200, status("https://cloudflare-ech.com/cdn-cgi/trace"));
        assertEquals(200, status("https://tls.browserleaks.com/json"));
    }

    private static int status(String url) throws Exception {
        OkHttpClient client = OkHttpClientFactory.create(ImpersonatorFactory.macChrome()).newHttpClient();
        try (Response response = client.newCall(new Request.Builder().url(url).build()).execute()) {
            assertEquals("the profile is an HTTP/2 one, so anything else is a different code path",
                    "h2", response.protocol().toString());
            return response.code();
        }
    }
}
