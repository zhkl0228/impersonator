package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.RealityConfig;
import org.bouncycastle.tls.TlsClientProtocol;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

class ImpersonateSSLSocketWrap extends ProvSSLSocketWrap {

    private static final Logger log = LoggerFactory.getLogger(ImpersonateSSLSocketWrap.class);

    private final Impersonator impersonator;

    /**
     * The REALITY half of this connection, or null for an ordinary TLS one. One instance per
     * connection, built here because it is the one place that makes both halves that need it: the
     * protocol writes the authentication into the ClientHello, the client checks the certificate it
     * comes back with, and the key is derived from this connection's own ClientHello.
     */
    private final RealityHandshake reality;

    ImpersonateSSLSocketWrap(ContextData contextData, Socket s, String host, int port, boolean autoClose, Impersonator impersonator) throws IOException {
        super(contextData, s, host, port, autoClose);
        this.impersonator = impersonator;
        RealityConfig realityConfig = impersonator.getRealityConfig();
        this.reality = realityConfig == null ? null : new RealityHandshake(realityConfig);
    }

    @Override
    protected TlsClientProtocol newProvTlsClientProtocol(InputStream input, OutputStream output, Closeable socketCloser) {
        return new ImpersonateProvTlsClientProtocol(input, output, socketCloser, impersonator, reality);
    }

    static void checkCipherSuites(ContextData contextData, int[] cipherSuites) {
        List<String> supportedCipherSuites = Arrays.asList(contextData.getSupportedCipherSuites());
        for (int cipherSuite : cipherSuites) {
            if (ImpersonatorFactory.isGrease(cipherSuite)) {
                continue;
            }
            String name = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
            if (name == null) {
                throw new IllegalArgumentException("cipherSuite=" + cipherSuite + ", cipherSuites=" + Arrays.toString(cipherSuites));
            }
            log.debug("cipherSuite={}, name={}", cipherSuite, name);
            if(!supportedCipherSuites.contains(name)) {
                log.warn("newProvTlsClient name={}, supportedCipherSuites={}", name, supportedCipherSuites);
            }
        }
    }

    @Override
    protected ProvTlsClient newProvTlsClient(ProvSSLParameters sslParameters) {
        int[] cipherSuites = impersonator.getCipherSuites();
        checkCipherSuites(contextData, cipherSuites);
        return new ImpersonateTlsClient(this, sslParameters, cipherSuites, impersonator, reality);
    }
}
