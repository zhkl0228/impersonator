package com.github.zhkl0228.impersonator;

public class MacChromeTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("4c9ce26028c11d7544da00d3f7e4f45c", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0",
                null, null, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
                "52d84b11737d980aef856699f885ca86", "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("58e05a62bade1452454ea0b0cc49c971", "version:772|ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281-GREASE|groups:GREASE-25497-29-23-24|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-25497-29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2(null, null,
                "4ce4894f9f13c1bd779df7c16ee5ec31",
                "Accept,Accept-Encoding,Accept-Language,Cache-Control,Cookie,Sec-Ch-Ua,Sec-Ch-Ua-Mobile,Sec-Ch-Ua-Platform,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,Sec-Fetch-User,Upgrade-Insecure-Requests,User-Agent");
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        return ImpersonatorFactory.macChrome();
    }
}
