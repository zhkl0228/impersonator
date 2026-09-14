package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/**
 * Support class for X25519 using the JCE.
 */
public class JceX25519 implements TlsAgreement
{
    protected final JceX25519Domain domain;

    protected KeyPair localKeyPair;
    protected PublicKey peerPublicKey;

    public JceX25519(JceX25519Domain domain)
    {
        this.domain = domain;
    }

    public byte[] generateEphemeral() throws IOException
    {
        this.localKeyPair = domain.generateKeyPair();

        return domain.encodePublicKey(localKeyPair.getPublic());
    }

    public void receivePeerValue(byte[] peerValue) throws IOException
    {
        this.peerPublicKey = domain.decodePublicKey(peerValue);
    }

    public TlsSecret calculateSecret() throws IOException
    {
        return domain.calculateECDHAgreement(localKeyPair.getPrivate(), peerPublicKey);
    }

    /**
     * The shared secret with a public key that is not the handshake peer's, leaving this agreement's
     * own state alone so the handshake it belongs to still completes. REALITY uses the client's
     * ephemeral key twice: against the server's long term public key, which is this, and against the
     * server's key share, which is {@link #calculateSecret()}.
     *
     * @throws IllegalStateException if called before {@link #generateEphemeral()}, since there is no
     *                               ephemeral key to agree with yet
     */
    public TlsSecret agreeWith(byte[] peerPublicKey) throws IOException
    {
        if (localKeyPair == null)
        {
            throw new IllegalStateException("no ephemeral key has been generated yet");
        }

        return domain.calculateECDHAgreement(localKeyPair.getPrivate(), domain.decodePublicKey(peerPublicKey));
    }
}
