package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class AndroidLINETest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("b6c462146270c94ed8e339bcf4fff25f", "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-21-23-35-43-45-51-65281,29-23-24,0",
                "f79b6bad2ad0641e1921aef10262856b", "771,4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("5e5fa879036958e46d208b946ff7c209", "version:772|ch_ciphers:4865-4866-4867-49195-49196-52393-49199-49200-52392-49171-49172-156-157-47-53|ch_extensions:0-5-10-11-13-16-23-35-43-45-51-65281|groups:29-23-24|points:0|compression:0|supported_versions:772-771|supported_protocols:h2-http11|key_shares:29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537-513|early_data:0|");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.androidLINE(null, new TrustManager[]{DefaultTrustManager.INSTANCE});
        return context.getSocketFactory();
    }

}
