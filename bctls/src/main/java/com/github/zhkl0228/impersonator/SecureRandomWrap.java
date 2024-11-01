package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ClientHello;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

class SecureRandomWrap extends SecureRandom implements Impersonator {

    private final Impersonator impersonator;

    SecureRandomWrap(Impersonator impersonator) {
        this.impersonator = impersonator;
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        byte[] seed = new byte[numBytes];
        ThreadLocalRandom.current().nextBytes(seed);
        return seed;
    }

    @Override
    public void nextBytes(byte[] bytes) {
        ThreadLocalRandom.current().nextBytes(bytes);
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
    public void onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException {
        impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
    }

}
