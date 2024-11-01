package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import org.bouncycastle.tls.TlsSession;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class ImpersonateProvTlsClientProtocol extends ProvTlsClientProtocol {

    private final Impersonator impersonator;

    ImpersonateProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable, Impersonator impersonator) {
        super(input, output, closeable);
        this.impersonator = impersonator;
    }

    @Override
    protected boolean establishSession(TlsSession sessionToResume) {
        try {
            impersonator.onEstablishSession(clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("establishSession", e);
        }
        return super.establishSession(sessionToResume);
    }

    @Override
    protected void sendClientHelloMessage() throws IOException {
        try {
            impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("sendClientHelloMessage", e);
        }
        super.sendClientHelloMessage();
    }
}
