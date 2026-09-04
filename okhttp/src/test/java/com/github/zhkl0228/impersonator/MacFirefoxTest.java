package com.github.zhkl0228.impersonator;

/**
 * Every expectation here is a verbatim capture from Firefox 155.0 on macOS, taken from the same
 * services the tests query.
 */
public class MacFirefoxTest extends SSLProviderTest {

    private static final String CIPHERS =
            "4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53";

    private static final String USER_AGENT =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:155.0) Gecko/20100101 Firefox/155.0";

    private static final String AKAMAI = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s";

    private static final String SIGNATURE_ALGS = "1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513";

    private static final String GROUPS = "4588-29-23-24-25-256-257";

    /** Sorted, as ja3n and the peetprint style fingerprints report it. */
    private static final String EXTENSIONS_SORTED = "0-10-11-13-16-18-23-27-28-34-35-43-45-5-51-65037-65281";

    /** The order Firefox actually sends them in; unlike Chrome it does not shuffle. */
    private static final String EXTENSIONS_ORDERED = "0-23-65281-10-11-35-16-5-34-18-51-43-13-45-28-27-65037";

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("771," + CIPHERS + ",0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281," + GROUPS + ",0",
                "771," + CIPHERS + "," + EXTENSIONS_ORDERED + "," + GROUPS + ",0",
                USER_AGENT, AKAMAI);
    }

    /**
     * The same extension set must survive inside the ClientHelloInner when the server name is
     * encrypted. This browser does ECH, so tls.browserleaks.com reports the inner here.
     */
    public void testBrowserLeaksEch() throws Exception {
        doTestBrowserLeaksEch("771," + CIPHERS + ",0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281," + GROUPS + ",0",
                USER_AGENT, AKAMAI);
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("version:772|ch_ciphers:" + CIPHERS
                + "|ch_extensions:0-5-10-11-13-16-18-23-27-28-34-35-43-45-51-65037-65281"
                + "|groups:" + GROUPS + "|points:0|compression:0|supported_versions:772-771"
                + "|supported_protocols:h2-http11|key_shares:4588-29-23|psk:1"
                + "|signature_algs:" + SIGNATURE_ALGS + "|early_data:0");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2(AKAMAI,
                "Accept,Accept-Encoding,Accept-Language,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Upgrade-Insecure-Requests,User-Agent",
                // Firefox 155's own order, except that okhttp appends accept-encoding last where
                // Firefox sends it right after accept-language.
                ":method,:path,:authority,:scheme,user-agent,accept,accept-language,"
                        + "upgrade-insecure-requests,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,"
                        + "sec-fetch-user,priority,te,accept-encoding");
    }

    public void testBrowserScan() throws Exception {
        doTestBrowserScan("t13d1517h2_8daaf6152771_a30fb921a1c0",
                "772-771|2-1.1|" + SIGNATURE_ALGS + "|1|1-2-3|" + GROUPS + "|" + CIPHERS
                        + "|" + EXTENSIONS_SORTED);
    }

    public void testPeetPrint() throws Exception {
        doTestPeetPrint("t13d1517h2_8daaf6152771_3cbfd9057e0d",
                "772-771|2-1.1|" + GROUPS + "|" + SIGNATURE_ALGS + "|1|1-2-3|" + CIPHERS
                        + "|" + EXTENSIONS_SORTED,
                AKAMAI,
                "771," + CIPHERS + "," + EXTENSIONS_ORDERED + "," + GROUPS + ",0");
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        return ImpersonatorFactory.macFirefox();
    }
}
