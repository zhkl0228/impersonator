package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class MacFirefoxTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("6de49d1869679eda9dccc6c9057cfd94", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281,29-23-24-25-256-257,0",
                "b5001237acdf006056b409cc433726b0", "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25-256-257,0");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("cd49226daab228974aa39a7a395f2841", "version:772|ch_ciphers:4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53|ch_extensions:0-5-10-11-13-16-23-28-34-35-43-45-51-65037-65281|groups:29-23-24-25-256-257|points:0|compression:0|supported_versions:772-771|supported_protocols:h2-http11|key_shares:29-23|psk:1|signature_algs:1027-1283-1539-2052-2053-2054-1025-1281-1537-515-513|early_data:0|");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.macFirefox(null, new TrustManager[]{DefaultTrustManager.INSTANCE});
        return context.getSocketFactory();
    }
}
