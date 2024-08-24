package org.bouncycastle.jsse.provider;

class ImpersonateTlsClient extends ProvTlsClient {

    private final int[] cipherSuites;

    ImpersonateTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters, int[] cipherSuites) {
        super(manager, sslParameters);
        this.cipherSuites = cipherSuites;
    }

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }
}
