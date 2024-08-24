package com.github.zhkl0228.impersonator.other;

import cn.hutool.core.io.FileUtil;
import cn.hutool.core.net.DefaultTrustManager;
import com.github.zhkl0228.impersonator.SSLProviderTest;
import org.wildfly.openssl.OpenSSLProvider;
import org.wildfly.openssl.SSL;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.File;

public class WildflyProviderTest extends SSLProviderTest {

    static {
        System.setProperty(SSL.ORG_WILDFLY_LIBWFSSL_PATH, new File(FileUtil.getUserHomeDir(), "git/wildfly-openssl-natives/macosx-aarch64/target/classes/macosx-aarch64/libwfssl.dylib").getAbsolutePath());
        System.setProperty(SSL.ORG_WILDFLY_OPENSSL_PATH, "/opt/local/lib");
        OpenSSLProvider.register();
    }

    public void testHttp() throws Exception {
        doTestBrowserLeaks();
    }

    @Override
    protected SSLSocketFactory createSSLSocketFactory() throws Exception {
        SSLContext context = SSLContext.getInstance("openssl.TLS");
        context.init(null, new TrustManager[]{DefaultTrustManager.INSTANCE}, null);
        return context.getSocketFactory();
    }

}
