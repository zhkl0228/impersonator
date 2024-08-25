package com.github.zhkl0228.impersonator;

import javax.net.ssl.SSLContext;

public class IOSTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("44f7ed5185d22c92b96da72dbe68d307", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-5-10-11-13-16-18-21-23-27-43-45-51-65281,29-23-24-25,0",
                "773906b0efdefa24a7f2b8eb6985bf37", "771,4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10,0-23-65281-10-11-16-5-13-18-51-45-43-27-21,29-23-24-25,0");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("f638ee5bf20fa34a65437016daa32cf7", "version:772|ch_ciphers:GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-43-45-51-65281-GREASE|groups:GREASE-29-23-24-25|points:0|compression:0|supported_versions:GREASE-772-771-770-769|supported_protocols:h2-http11|key_shares:GREASE-29|psk:1|signature_algs:1027-2052-1025-1283-515-2053-2053-1281-2054-1537-513|early_data:0|");
    }

    @Override
    protected SSLContext createSSLContext() {
        return ImpersonatorFactory.ios().newSSLContext();
    }
}
