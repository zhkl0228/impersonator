package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
import org.conscrypt.OpenSSLProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.Security;

public class ConscryptProviderTest extends SSLProviderTest {

    static {
        Security.addProvider(new OpenSSLProvider());
    }

    public void testHttp() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "Conscrypt");
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
        return context.getSocketFactory();
    }

}
