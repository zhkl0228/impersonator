package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.SecureRandom;

/**
 * Builds the {@link RealityJcaTlsCrypto} a REALITY {@code SSLContext} runs on. Everything else is
 * {@link JcaTlsCryptoProvider}'s, this only decides which crypto object comes out.
 */
public class RealityJcaTlsCryptoProvider extends JcaTlsCryptoProvider {

    @Override
    public JcaTlsCrypto create(SecureRandom keyRandom, SecureRandom nonceRandom) {
        return new RealityJcaTlsCrypto(getHelper(), getAltHelper(), keyRandom, nonceRandom);
    }
}
