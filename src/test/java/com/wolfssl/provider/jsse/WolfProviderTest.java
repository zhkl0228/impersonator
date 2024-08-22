package com.wolfssl.provider.jsse;

import cn.hutool.core.net.DefaultTrustManager;
import com.github.zhkl0228.impersonator.SSLProviderTest;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import org.scijava.nativelib.NativeLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.SecureRandom;
import java.security.Security;

public class WolfProviderTest extends SSLProviderTest {

    static {
        try {
            NativeLoader.loadLibrary("wolfssljni");
            Security.addProvider(new WolfSSLProvider());
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }
    }

    public void testHttp() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected final SSLSocketFactory createSSLSocketFactory() throws Exception {
        {
            SSLContext context = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
            assertNotNull(context);
            X509TrustManager trustManager = new DefaultTrustManager();
            context.init(null, new TrustManager[]{trustManager}, null);
        }
        com.wolfssl.WolfSSLContext context = new WolfSSLContext(WolfSSL.TLSv1_3_Method());
        context.setCipherList("TLS_AES_128_GCM_SHA256");
        WolfSSLAuthStore authStore = new WolfSSLAuthStore(null, new TrustManager[]{new DefaultTrustManager()}, new SecureRandom(), WolfSSL.TLS_VERSION.TLSv1_3);
        WolfSSLParameters parameters = new WolfSSLParameters();
        parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        parameters.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        return new WolfSSLSocketFactory(context, authStore, parameters);
    }

}
