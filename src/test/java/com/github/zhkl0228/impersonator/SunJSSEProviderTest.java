package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

public class SunJSSEProviderTest extends SSLProviderTest {

    public void testHttp() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3");
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
        return context.getSocketFactory();
    }

}
