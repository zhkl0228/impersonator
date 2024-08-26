package com.github.zhkl0228.impersonator.other;

import com.wolfssl.provider.jsse.WolfSSLProvider;
import org.scijava.nativelib.NativeLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.security.Security;

public class WolfProviderTest extends OtherProviderTest {

    static {
        try {
            NativeLoader.loadLibrary("wolfssljni");
            Security.addProvider(new WolfSSLProvider());
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }
    }

    public void testBrowserLeaks() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLContext createSSLContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
        assertNotNull(context);
        context.init(null, new TrustManager[]{this}, null);
        return context;
    }
}
