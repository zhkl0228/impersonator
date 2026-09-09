package com.github.zhkl0228.impersonator.quic;

/**
 * Told when a server rejected the ECHConfig that was offered for a host, so that the caller can
 * remember what the server wants to be retried with. RFC 9849 section 6.1.6.
 * <p>
 * The rejection is authenticated by the time this is called: the handshake ran to the end and the
 * certificate presented for {@code publicName} was verified, so the retry configs are the server's
 * own. The connection itself is failed either way; nothing here retries.
 */
public interface EchRejectionHandler {

    /**
     * @param serverName   the real server name the connection was for.
     * @param publicName   the {@code ECHConfig.contents.public_name} that was sent in the clear and
     *                     that the certificate was verified against.
     * @param retryConfigs the raw ECHConfigList to offer for {@code serverName} next time, or null
     *                     if the server sent none, which means Encrypted Client Hello should be
     *                     switched off for this host.
     */
    void echRejected(String serverName, String publicName, byte[] retryConfigs);

}
