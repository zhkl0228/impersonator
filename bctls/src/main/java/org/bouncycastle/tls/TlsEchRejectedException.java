package org.bouncycastle.tls;

/**
 * Thrown when Encrypted Client Hello was offered and the server did not accept it, so the real
 * server name was never protected. RFC 9849 section 6.1.6.
 * <p>
 * The handshake still runs to EncryptedExtensions against the ClientHelloOuter, because that is
 * where the server publishes the {@code retry_configs} to use next time. Retrying is the caller's
 * decision: the {@code retry_configs} are only trustworthy once the certificate presented for
 * {@link #getPublicName()} has been verified, which happens above this layer.
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
