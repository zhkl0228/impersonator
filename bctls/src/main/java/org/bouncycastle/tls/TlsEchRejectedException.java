package org.bouncycastle.tls;

/**
 * Thrown when Encrypted Client Hello was offered and the server did not accept it, so the real
 * server name was never protected. RFC 9849 section 6.1.7.
 * <p>
 * The handshake still runs against the ClientHelloOuter, far enough to read the
 * {@code retry_configs} out of EncryptedExtensions and then to authenticate the connection: the
 * certificate chain is validated, its CertificateVerify is checked, and it must name
 * {@link #getPublicName()}. Only then is this thrown. Without that the rejection would be
 * unauthenticated, and an on-path attacker could force one and pick the
 * {@link #getRetryConfigs() retry configs} the caller remembers for its next connection.
 * <p>
 * Whether to retry is still the caller's decision; this library does not retry by itself.
 */
public class TlsEchRejectedException
    extends TlsFatalAlert
{
    private final String publicName;
    private final byte[] retryConfigs;

    TlsEchRejectedException(String publicName, byte[] retryConfigs, String detailMessage)
    {
        super(AlertDescription.ech_required, detailMessage);

        this.publicName = publicName;
        this.retryConfigs = retryConfigs;
    }

    /**
     * The {@code ECHConfig.contents.public_name} that was offered as the ClientHelloOuter's server
     * name. The server's certificate must be verified against this name before the
     * {@link #getRetryConfigs() retry configs} may be used.
     */
    public String getPublicName()
    {
        return publicName;
    }

    /**
     * The raw ECHConfigList the server wants to be retried with, or null if it sent none, which
     * means Encrypted Client Hello should be disabled for this server.
     */
    public byte[] getRetryConfigs()
    {
        return retryConfigs;
    }
}
