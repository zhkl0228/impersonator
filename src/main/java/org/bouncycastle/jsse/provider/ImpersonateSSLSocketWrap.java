package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsClientProtocol;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

class ImpersonateSSLSocketWrap extends ProvSSLSocketWrap {

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
        return new ImpersonateTlsClient(this, sslParameters, impersonator.getCipherSuites());
    }
}
