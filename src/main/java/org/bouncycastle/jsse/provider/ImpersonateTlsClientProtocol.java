package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.TlsSession;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class ImpersonateTlsClientProtocol extends ProvTlsClientProtocol {

    private final Impersonator impersonator;

    ImpersonateTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable, Impersonator impersonator) {
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
}
