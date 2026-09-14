package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.RealityConfig;
import org.bouncycastle.tls.TlsClientProtocol;

class ImpersonateSSLEngine extends ProvSSLEngine {

    private final Impersonator impersonator;

    /** As on the socket path: one per connection, shared by the protocol and the client. */
    private final RealityHandshake reality;

    ImpersonateSSLEngine(ContextData contextData, String peerHost, int peerPort, Impersonator impersonator) {
        super(contextData, peerHost, peerPort);
        this.impersonator = impersonator;
        RealityConfig realityConfig = impersonator.getRealityConfig();
        this.reality = realityConfig == null ? null : new RealityHandshake(realityConfig);
    }

    @Override
    protected TlsClientProtocol newTlsClientProtocol() {
        return new ImpersonateTlsClientProtocol(impersonator, reality);
    }

    @Override
    protected ProvTlsClient newProvTlsClient(ProvSSLParameters sslParameters) {
        int[] cipherSuites = impersonator.getCipherSuites();
        ImpersonateSSLSocketWrap.checkCipherSuites(contextData, cipherSuites);
        return new ImpersonateTlsClient(this, sslParameters, cipherSuites, impersonator, reality);
    }
}
