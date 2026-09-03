package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;

class ImpersonateTlsClient extends ProvTlsClient {

    private final int[] cipherSuites;
    private final Impersonator impersonator;

    ImpersonateTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters, int[] cipherSuites,
                         Impersonator impersonator) {
        super(manager, sslParameters);
        this.cipherSuites = cipherSuites;
        this.impersonator = impersonator;
    }

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    /**
     * The ECHConfigList is looked up by the same name that would otherwise be sent as a plaintext
     * SNI, so that the caller's provider is keyed on the host it knows about.
     */
    @Override
    public byte[] getEchConfigList() {
        return impersonator.getEchConfigList(JsseUtils.stripTrailingDot(manager.getPeerHostSNI()));
    }
}
