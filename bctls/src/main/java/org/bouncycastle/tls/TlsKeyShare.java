package org.bouncycastle.tls;

import java.io.IOException;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsCrypto;

/**
 * One key_share entry's key exchange, usable without a {@link TlsProtocol} driving it.
 * <p>
 * The QUIC path builds its own ClientHello - the TLS 1.3 handshake there is agent15's, not this
 * library's - but still has to produce key shares for the groups a browser offers, X25519MLKEM768
 * among them. Rather than reimplement the hybrid construction (which half goes first in the share,
 * where the peer's value splits, how the two secrets concatenate), this exposes the one BouncyCastle
 * already has: {@code TlsUtils.createKeyShare}, which is package private.
 */
public class TlsKeyShare
{
    private final int namedGroup;
    private final TlsAgreement agreement;

    private TlsKeyShare(int namedGroup, TlsAgreement agreement)
    {
        this.namedGroup = namedGroup;
        this.agreement = agreement;
    }

    /**
     * @param namedGroup a {@link NamedGroup} value.
     * @throws IOException if this crypto cannot do the group, which for a caller that chose the group
     *             itself means a misconfiguration and not a negotiation failure.
     */
    public static TlsKeyShare create(TlsCrypto crypto, int namedGroup) throws IOException
    {
        TlsAgreement agreement = TlsUtils.createKeyShare(crypto, namedGroup, false);
        if (null == agreement)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error, "no key exchange for named group "
                + NamedGroup.getText(namedGroup) + " (0x" + Integer.toHexString(namedGroup) + ")");
        }
        return new TlsKeyShare(namedGroup, agreement);
    }

    public int getNamedGroup()
    {
        return namedGroup;
    }

    /** The client's key exchange value, i.e. the {@code key_exchange} of the key_share entry. */
    public byte[] generateEphemeral() throws IOException
    {
        return agreement.generateEphemeral();
    }

    /**
     * @param peerValue the server's key_share {@code key_exchange}, exactly as it arrived.
     * @return the shared secret, which is what the TLS 1.3 key schedule takes as the (EC)DHE input.
     */
    public byte[] calculateSecret(byte[] peerValue) throws IOException
    {
        agreement.receivePeerValue(peerValue);
        return agreement.calculateSecret().extract();
    }
}
