package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ClientHello;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

class SecureRandomWrap extends SecureRandom implements Impersonator {

    private final Impersonator impersonator;

    /** Null for an ordinary context; see {@link ImpersonatorApi#newRealityContext}. */
    private final RealityConfig realityConfig;

    SecureRandomWrap(Impersonator impersonator) {
        this(impersonator, null);
    }

    SecureRandomWrap(Impersonator impersonator, RealityConfig realityConfig) {
        this.impersonator = impersonator;
        this.realityConfig = realityConfig;
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
    public int[] getKeyShareGroups() {
        return impersonator.getKeyShareGroups();
    }

    @Override
    public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
        impersonator.onEstablishSession(clientExtensions);
    }

    @Override
    public ExtensionOrder onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException {
        return impersonator.onSendClientHelloMessage(clientHello, clientExtensions);
    }

    @Override
    public byte[] getEchConfigList(String host) {
        return impersonator.getEchConfigList(host);
    }

    /**
     * This context's REALITY parameters rather than the profile's: the profile has none, because it
     * may be shared by outbounds that are not REALITY at all.
     */
    @Override
    public RealityConfig getRealityConfig() {
        return realityConfig;
    }

}
