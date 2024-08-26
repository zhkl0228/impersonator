package com.github.zhkl0228.impersonator;

public class MacFirefoxTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("6de49d1869679eda9dccc6c9057cfd94", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0",
                "b5001237acdf006056b409cc433726b0", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0",
                "3d9132023bf26a71d40fe766e5c24c9d", "1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("cd49226daab228974aa39a7a395f2841", "version:772|ch_ciphers:4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|ch_extensions:0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281|groups:29-23-24-25-256-257|points:0|compression:0|supported_versions:772-771|supported_protocols:h2-http11|key_shares:29-23|psk:1|signature_algs:1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|early_data:0|");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestScrapFlyHttp2("465f406497853d8675907d5be901caca",
                "1:65536;4:131072;5:16384|12517377|3:1:0:201,5:1:0:101,7:1:0:1,9:1:7:1,11:1:3:1,13:1:0:241|m,p,a,s");
    }

    @Override
    protected ImpersonatorApi createImpersonatorApi() {
        return ImpersonatorFactory.macFirefox();
    }
}
