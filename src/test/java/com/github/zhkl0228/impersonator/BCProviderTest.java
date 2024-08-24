package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.ImpersonateSecureRandom;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.security.Security;

public class BCProviderTest extends SSLProviderTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
    }

    public void testHttp() throws Exception {
        doTestBrowserLeaks();
    }

    public void testScrapFlyJa3() throws Exception {
        doTestURL("https://tools.scrapfly.io/api/fp/ja3");
    }

    public void testScrapFlyHttp2() throws Exception {
        doTestURL("https://tools.scrapfly.io/api/http2");
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", BouncyCastleJsseProvider.PROVIDER_NAME);
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, ImpersonateSecureRandom.chrome());
        return context.getSocketFactory();
    }

}
