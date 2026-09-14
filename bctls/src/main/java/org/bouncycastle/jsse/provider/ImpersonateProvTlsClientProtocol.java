package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.ExtensionOrder;
import com.github.zhkl0228.impersonator.Impersonator;
import org.bouncycastle.tls.TlsSession;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

class ImpersonateProvTlsClientProtocol extends ProvTlsClientProtocol {

    private final Impersonator impersonator;

    private final RealityHandshake reality;

    ImpersonateProvTlsClientProtocol(InputStream input, OutputStream output, Closeable closeable, Impersonator impersonator,
                                     RealityHandshake reality) {
        super(input, output, closeable);
        this.impersonator = impersonator;
        this.reality = reality;
    }

    /**
     * REALITY's authentication replaces the ClientHello's legacy_session_id and is computed over the
     * rest of that same message, so it can only be written once the message is encoded - after the
     * profile has had its say about the extensions and their order, and before the transcript hash
     * sees any of it.
     */
    @Override
    protected void onClientHelloEncoded(byte[] message, int length) throws IOException {
        if (reality != null) {
            reality.sealClientHello(clientHello, message, length, clientAgreements);
        }
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
        ExtensionOrder extensionOrder;
        try {
            extensionOrder = impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
        } catch (IOException e) {
            throw new IllegalStateException("sendClientHelloMessage", e);
        }
        int[] supportedGroups = impersonator.getKeyShareGroups();
        if(supportedGroups != null && supportedGroups.length > 0) {
            this.clientAgreements = ImpersonateTlsClientProtocol.updateKeyShareToClientHello(tlsClientContext, clientExtensions, supportedGroups);
        }
        if (extensionOrder != null) {
            extensionOrder.sort(clientExtensions);
        }
        super.sendClientHelloMessage();
    }
}
