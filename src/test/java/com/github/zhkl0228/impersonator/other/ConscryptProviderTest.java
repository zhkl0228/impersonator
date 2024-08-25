package com.github.zhkl0228.impersonator.other;

import com.github.zhkl0228.impersonator.SSLProviderTest;
import org.conscrypt.OpenSSLProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.Security;

public class ConscryptProviderTest extends SSLProviderTest {

    static {
        Security.addProvider(new OpenSSLProvider());
    }

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "Conscrypt");
        context.init(null, new TrustManager[]{this}, null);
        return context.getSocketFactory();
    }

}
