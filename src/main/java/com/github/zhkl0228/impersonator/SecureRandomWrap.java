package com.github.zhkl0228.impersonator;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;

class SecureRandomWrap extends SecureRandom implements Impersonator {

    private final Impersonator impersonator;

    SecureRandomWrap(Impersonator impersonator) {
        this.impersonator = impersonator;
    }

    @Override
    public int[] getCipherSuites() {
        return impersonator.getCipherSuites();
    }

    @Override
    public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
        impersonator.onEstablishSession(clientExtensions);
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        impersonator.onSendClientHelloMessage(clientExtensions);
    }

}
