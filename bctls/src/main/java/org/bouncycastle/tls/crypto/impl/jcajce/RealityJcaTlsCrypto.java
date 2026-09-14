package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.CertificateType;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * The crypto a REALITY connection uses, which differs from {@link JcaTlsCrypto} in one thing: the
 * server's certificate is read as {@link RealityTlsCertificate} rather than as an X.509 one, because
 * REALITY's temporary certificate is not a valid X.509 certificate and no Java parser will take it.
 * <p>
 * Chosen per {@code SSLContext} rather than per connection, which is exactly how REALITY is
 * configured: an {@code ImpersonatorApi} with a {@code RealityConfig} makes REALITY connections and
 * nothing else, so no connection made through this crypto should ever be handed an ordinary
 * certificate. One that is fails loudly here instead of being quietly accepted - which matters,
 * because that is precisely what a REALITY server does to a client it rejects: it forwards the
 * connection to the real website, whose certificate is perfectly valid and is not the server's.
 */
class RealityJcaTlsCrypto extends JcaTlsCrypto {

    RealityJcaTlsCrypto(JcaJceHelper helper, JcaJceHelper altHelper, SecureRandom entropySource,
                        SecureRandom nonceEntropySource) {
        super(helper, altHelper, entropySource, nonceEntropySource);
    }

    @Override
    public TlsCertificate createCertificate(short type, byte[] encoding) throws IOException {
        if (CertificateType.X509 != type) {
            throw new TlsFatalAlert(AlertDescription.unsupported_certificate,
                    "a REALITY server sends an X.509 certificate, this one sent certificate type " + type);
        }
        return new RealityTlsCertificate(this, encoding);
    }
}
