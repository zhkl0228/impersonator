package com.github.zhkl0228.impersonator.other;

import cn.hutool.core.net.DefaultTrustManager;
import com.github.zhkl0228.impersonator.SSLProviderTest;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class SunJSSEProviderTest extends SSLProviderTest {

    public void testScrapFlyHttp2() throws Exception {
        doTestURL("https://tools.scrapfly.io/api/http2");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
        return context.getSocketFactory();
    }

}