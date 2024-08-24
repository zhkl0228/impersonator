package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
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

    ImpersonateSSLSocketWrap(ContextData contextData, Socket s, String host, int port, boolean autoClose, Impersonator impersonator) throws IOException {
        super(contextData, s, host, port, autoClose);
        this.impersonator = impersonator;
    }

    @Override
    protected TlsClientProtocol newProvTlsClientProtocol(InputStream input, OutputStream output, Closeable socketCloser) {
        return new ImpersonateTlsClientProtocol(input, output, socketCloser, impersonator);
    }

    /**
     * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described here:
     * <a href="https://tools.ietf.org/html/draft-davidben-tls-grease-01">draft-davidben-tls-grease-01</a>.
     */
    private static final int[] GREASE = new int[] { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa };

    private static boolean isGrease(int value) {
        for (int grease : GREASE) {
            if (grease == value) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected ProvTlsClient newProvTlsClient(ProvSSLParameters sslParameters) {
        ProvSSLContextSpi context = contextData.getContext();
        List<String> supportedCipherSuites = Arrays.asList(context.getSupportedCipherSuites());
        int[] cipherSuites = impersonator.getCipherSuites();
        for (int cipherSuite : cipherSuites) {
            if (isGrease(cipherSuite)) {
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
        return new ImpersonateTlsClient(this, sslParameters, cipherSuites);
    }
}
