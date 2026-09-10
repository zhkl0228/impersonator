package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

/**
 * The field section each profile writes over HTTP/3, asserted against the order its HTTP/2 tests
 * already pin against a capture of the browser.
 * <p>
 * Those two orders have to be the same. One browser builds one request; whether it then goes out
 * through HPACK or QPACK is a transport detail below the point where the header list is decided. So
 * these expectations are copied from MacChromeTest, MacSafariTest and MacFirefoxTest deliberately -
 * if the HTTP/2 order is ever corrected against a new capture, these fail until they are corrected
 * with it, which is the point.
 * <p>
 * Asserted from inside rather than from an endpoint's report because no endpoint reachable from here
 * reports the field order it received over HTTP/3. The HTTP/2 one does, and that is where the orders
 * came from; here the connection is asked what it wrote.
 */
public class RequestHeaderOrderTest extends TestCase {

    private static final String URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** MacChromeTest's order, which came from an address bar navigation. */
    public void testChromeSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macChrome(),
                ":method,:authority,:scheme,:path,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,"
                        + "upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,"
                        + "sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority");
    }

    /** MacSafariTest's order. Safari alone puts sec-fetch-dest before its user agent. */
    public void testSafariSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macSafari(),
                ":method,:scheme,:authority,:path,sec-fetch-dest,user-agent,accept,sec-fetch-site,"
                        + "sec-fetch-mode,accept-language,priority,accept-encoding");
    }

    /** MacFirefoxTest's order. Firefox alone sends a TE, and sends it last. */
    public void testFirefoxSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macFirefox(),
                ":method,:path,:authority,:scheme,user-agent,accept,accept-language,accept-encoding,"
                        + "upgrade-insecure-requests,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,"
                        + "sec-fetch-user,priority,te");
    }

    /**
     * The three orders are three orders, which is the reason any of this is worth doing: the four
     * pseudo headers alone tell the three browsers apart, before a single field is read.
     */
    public void testTheThreeBrowsersDoNotShareAnOrder() {
        assertEquals("m,a,s,p", pseudoOrder(ImpersonatorFactory.macChrome()));
        assertEquals("m,s,a,p", pseudoOrder(ImpersonatorFactory.macSafari()));
        assertEquals("m,p,a,s", pseudoOrder(ImpersonatorFactory.macFirefox()));
    }

    private static String pseudoOrder(ImpersonatorApi api) {
        return ((Impersonator) api).getPseudoHeaderOrder();
    }

    private static void assertFieldSection(ImpersonatorApi api, String expected) throws Exception {
        try (Http3Client client = (Http3Client) Http3ClientFactory.create(api).newHttpClient()) {
            URI uri = URI.create(URL);
            int status = client.send(HttpRequest.newBuilder(uri).build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode();
            assertEquals("the endpoint answers only over HTTP/3", 200, status);

            List<String> written = client.openConnection(uri.getHost() + ":443").lastFieldSection();
            assertNotNull("the profile declared no field order, so nothing was reordered", written);
            assertEquals(expected, String.join(",", written));
        }
    }
}
