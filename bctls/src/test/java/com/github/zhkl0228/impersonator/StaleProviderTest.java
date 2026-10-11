package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import java.net.Socket;
import java.security.Provider;
import java.security.Security;

/**
 * A provider left behind under the name "BCJSSE" must not be what a context is built on.
 * <p>
 * The Security provider list is JVM-wide and outlives a web application. After a hot redeploy the
 * name still resolves to the instance the previous deployment registered, whose class loader is
 * closed; a context looked up by that name fails with NoClassDefFoundError on the first class the old
 * instance had not loaded yet (2026-10-11 in Tomcat: SSLSocketUtil, on every connection until a
 * restart). Here the leftover is a stand-in registered under the same name, and the context has to
 * come from the factory's own instance and still complete a handshake.
 */
public class StaleProviderTest extends TestCase {

    private static final String HOST = "www.cloudflare.com";

    public void testContextIgnoresWhateverIsRegisteredUnderTheName() throws Exception {
        ImpersonatorApi api = ImpersonatorFactory.macSafari();
        Provider registered = Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        @SuppressWarnings("deprecation")
        Provider leftover = new Provider(BouncyCastleJsseProvider.PROVIDER_NAME, 0, "left behind by a previous deployment") {
            private static final long serialVersionUID = 1L;
        };
        Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
        Security.addProvider(leftover);
        try {
            SSLContext context = api.newSSLContext(null, null);
            assertTrue("built on " + context.getProvider(), context.getProvider() instanceof BouncyCastleJsseProvider);
            assertNotSame(leftover, context.getProvider());
            // The impersonating factory only wraps an already connected socket, as okhttp does.
            try (Socket plain = new Socket(HOST, 443);
                 SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, HOST, 443, true)) {
                socket.startHandshake();
                assertTrue(socket.getSession().getPeerCertificates().length > 0);
            }
        } finally {
            Security.removeProvider(BouncyCastleJsseProvider.PROVIDER_NAME);
            if (registered != null) {
                Security.addProvider(registered);
            }
        }
    }

}
