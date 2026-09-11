package com.github.zhkl0228.impersonator.http3.core;

import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import junit.framework.TestCase;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * The field section a connection from {@link Http3ConnectionFactory} writes, read back from the
 * server that received it.
 * <p>
 * Two claims, and the second is the reason this test is in this module rather than the one above it.
 * The first is that the order is the browser's - the same order the HTTP/2 tests pin against captures,
 * because one browser builds one request and whether it then goes out through HPACK or QPACK is a
 * transport detail below the point where the header list is decided. The second is that the browser's
 * headers and their order arrive here without anyone above asking for them: no
 * {@link java.net.http.HttpClient}, no client class, nothing but a connection and a request with no
 * headers on it at all. That is what moving fillRequestHeaders down here was for.
 * <p>
 * Asserted from the server's side rather than from what this end recorded writing. The public
 * endpoints report HTTP/2 field order and not HTTP/3, which is why the test in impersonator-http3
 * asks the connection what it wrote; the endpoint here is this project's own and exists for exactly
 * this - see docs/tools/h3_field_echo.py, which answers with the field section as it arrived.
 */
public class RequestFieldOrderTest extends TestCase {

    /** Any path; it answers all of them, so the path says who asked. */
    private static final String URL = "https://gzmtx.cn:8444/field-order";

    /** MacChromeTest's order, which came from an address bar navigation. */
    public void testChromeSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macChrome(), "m,a,s,p",
                ":method,:authority,:scheme,:path,sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,"
                        + "upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,"
                        + "sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,priority");
    }

    /** MacSafariTest's order. Safari alone puts sec-fetch-dest before its user agent. */
    public void testSafariSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macSafari(), "m,s,a,p",
                ":method,:scheme,:authority,:path,sec-fetch-dest,user-agent,accept,sec-fetch-site,"
                        + "sec-fetch-mode,accept-language,priority,accept-encoding");
    }

    /** MacFirefoxTest's order. Firefox alone sends a TE, and sends it last. */
    public void testFirefoxSendsItsOwnFieldOrder() throws Exception {
        assertFieldSection(ImpersonatorFactory.macFirefox(), "m,p,a,s",
                ":method,:path,:authority,:scheme,user-agent,accept,accept-language,accept-encoding,"
                        + "upgrade-insecure-requests,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,"
                        + "sec-fetch-user,priority,te");
    }

    /**
     * A header the caller adds keeps the place it was added in, after the browser's own.
     * <p>
     * Which is the honest half of the ordering: where a browser would put a Cookie or a Content-Type
     * of the caller's is not something any capture here shows, so those are not slotted somewhere
     * invented. What the captures do show is where the browser's own headers go, and this checks that
     * adding one of the caller's does not disturb them.
     */
    public void testACallersOwnHeaderGoesAfterTheBrowsersAndTheRestStayPut() throws Exception {
        JSONObject echoed = fieldSection(ImpersonatorFactory.macChrome(),
                HttpRequest.newBuilder(URI.create(URL)).header("x-caller", "mine"));
        String section = echoed.getString("field_section").replace("\"", "");

        assertTrue("the caller's header did not arrive: " + section, section.contains("x-caller"));
        assertTrue("it displaced the browser's, which start at the pseudo headers: " + section,
                section.startsWith("[:method,:authority,:scheme,:path,sec-ch-ua,"));
        assertTrue("and it belongs at the end, where nothing claims to know a browser's place for it",
                section.endsWith("priority,x-caller]"));
    }

    private static void assertFieldSection(ImpersonatorApi api, String pseudoOrder, String expected)
            throws Exception {
        JSONObject echoed = fieldSection(api, HttpRequest.newBuilder(URI.create(URL)));

        assertEquals("the pseudo header order the server saw", pseudoOrder,
                echoed.getString("pseudo_header_order"));
        assertEquals("the whole field section, as the server received it", expected,
                String.join(",", echoed.getJSONArray("field_section").toJavaList(String.class)));
    }

    /**
     * One request through a connection from the factory, and what the server says it received.
     * <p>
     * The request is built with no headers on it, so everything the endpoint reports beyond the
     * pseudo headers was added by the connection.
     */
    private static JSONObject fieldSection(ImpersonatorApi api, HttpRequest.Builder request)
            throws Exception {
        Http3ConnectionFactory factory = Http3ConnectionFactory.create(api);
        try (Http3Connection connection = factory.newConnection(URI.create(URL))) {
            HttpResponse<String> response =
                    connection.send(request.build(), HttpResponse.BodyHandlers.ofString());
            assertEquals("the endpoint answers only over HTTP/3, got: " + response.body(),
                    200, response.statusCode());
            return JSONObject.parseObject(response.body());
        }
    }
}
