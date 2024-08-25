package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
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

    @Override
    protected ProvTlsClient newProvTlsClient(ProvSSLParameters sslParameters) {
        ProvSSLContextSpi context = contextData.getContext();
        List<String> supportedCipherSuites = Arrays.asList(context.getSupportedCipherSuites());
        int[] cipherSuites = impersonator.getCipherSuites();
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
        return new ImpersonateTlsClient(this, sslParameters, cipherSuites);
    }
}
