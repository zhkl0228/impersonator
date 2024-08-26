package com.github.zhkl0228.impersonator;

public class MacSafariTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("44f7ed5185d22c92b96da72dbe68d307", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
                "773906b0efdefa24a7f2b8eb6985bf37", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                "dda308d35f4e5db7b52a61720ca1b122", "4:4194304;3:100|10485760|0|m,s,p,a");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("f638ee5bf20fa34a65437016daa32cf7", "version:772|ch_ciphers:GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-43-45-51-65281-GREASE|groups:GREASE-29-23-24-25|points:0|compression:0|supported_versions:GREASE-772-771-770-769|supported_protocols:h2-http11|key_shares:GREASE-29|psk:1|signature_algs:1027-2052-1025-1283-515-2053-2053-1281-2054-1537-513|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2("dda308d35f4e5db7b52a61720ca1b122",
                "4:4194304;3:100|10485760|0|m,s,p,a",
                "03910fa9e244d2d43cffc2409166e663",
                "Accept,Accept-Encoding,Accept-Language,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,User-Agent");
    }

    public void testBrowserScan() throws Exception {
        doTestBrowserScan("t13d2014h2_a09f3c656075_87f85be62a52",
                "e1730e79f9b04a90f132376a68c013ad", "GREASE-772-771-770-769|2-1.1|1027-2052-1025-1283-515-2053-2053-1281-2054-1537-513|1|1|GREASE-29-23-24-25|GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|0-10-11-13-16-18-21-23-27-43-45-5-51-65281-GREASE-GREASE");
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        return ImpersonatorFactory.macSafari();
    }
}
