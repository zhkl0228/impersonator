package com.github.zhkl0228.impersonator;

public class IOSTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-23-27-43-45-51-65281,4588-29-23-24-25,0",
                "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1",
                "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("version:772|ch_ciphers:GREASE-4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-43-45-51-65281-GREASE|groups:GREASE-4588-29-23-24-25|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-4588-29|psk:1|signature_algs:1027-2052-1025-1283-2053-2053-1281-2054-1537-513|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2(
                "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
                "Accept,Accept-Encoding,Accept-Language,Sec-Fetch-Dest,Sec-Fetch-Mode,Sec-Fetch-Site,User-Agent");
    }

    public void testBrowserScan() throws Exception {
        doTestBrowserScan("t13d2013h2_a09f3c656075_a2c20ee51d0d",
                "GREASE-772-771|2-1.1|1027-2052-1025-1283-2053-2053-1281-2054-1537-513|1|1|GREASE-4588-29-23-24-25|GREASE-4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|0-10-11-13-16-18-23-27-43-45-5-51-65281-GREASE-GREASE");
    }

    public void testPeetPrint() throws Exception {
        doTestPeetPrint("t13d2013h2_a09f3c656075_7f0f34a4126d",
                "GREASE-772-771|2-1.1|GREASE-4588-29-23-24-25|1027-2052-1025-1283-2053-2053-1281-2054-1537-513|1|1|GREASE-4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|0-10-11-13-16-18-23-27-43-45-5-51-65281-GREASE-GREASE",
                "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
                "771,4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27,4588-29-23-24-25,0");
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        return ImpersonatorFactory.ios();
    }
}
