package com.github.zhkl0228.impersonator.other;

import org.conscrypt.OpenSSLProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.Security;

public class ConscryptProviderTest extends OtherProviderTest {

    static {
        Security.addProvider(new OpenSSLProvider());
    }

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLContext createSSLContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "Conscrypt");
        context.init(null, new TrustManager[]{this}, null);
        return context;
    }
}
