package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import org.scijava.nativelib.NativeLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
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
        SSLContext context = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
        assertNotNull(context);
        X509TrustManager trustManager = new DefaultTrustManager();
        context.init(null, new TrustManager[]{trustManager}, null);
        return context.getSocketFactory();
    }

}
