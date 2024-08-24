package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class IOSLineTest extends SSLProviderTest {

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks("efb342b74b34e6332a96c9dfa43b7c1a", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49172-49161-49171-156-157-47-53,0-10-11-13-16-21-23-35-43-45-51-65281,29-23-24,0",
                "2d4744fdbac9faaecb1f2b67c2141a13", "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49172-49161-49171-156-157-47-53,0-23-65281-10-11-35-16-13-51-45-43-21,29-23-24,0");
    }

    public void testScrapFlyJa3() throws Exception {
        doTestScrapFlyJa3("cf06439086b03958cd5bc38a60924613", "version:772|ch_ciphers:4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49172-49161-49171-156-157-47-53|ch_extensions:0-10-11-13-16-23-35-43-45-51-65281|groups:29-23-24|points:0|compression:0|supported_versions:772-771|supported_protocols:h2-http11|key_shares:29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537-513|early_data:0|");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() {
        SSLContext context = ImpersonatorFactory.iosLINE(null, new TrustManager[]{DefaultTrustManager.INSTANCE});
        return context.getSocketFactory();
    }

}
