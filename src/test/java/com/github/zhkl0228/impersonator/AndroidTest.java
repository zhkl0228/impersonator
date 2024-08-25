package com.github.zhkl0228.impersonator;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class AndroidTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("473f0e7c0b6a0f7b049072f4e683068b", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0",
                null, null);
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("d808cea96540033e491725f4320273b5", "version:772|ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281-GREASE|groups:GREASE-29-23-24|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537|early_data:0|");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.android().newSSLContext();
        return context.getSocketFactory();
    }

}
