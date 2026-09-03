package com.github.zhkl0228.impersonator;

/**
 * Supplies the ECHConfigList to offer for a given host, so that the real server name travels inside
 * an encrypted ClientHelloInner instead of a plaintext SNI.
 * <p>
 * A browser reads this from the {@code ech} service parameter of the host's DNS HTTPS RR (RFC 9460).
 * This library does not resolve HTTPS RRs, so the caller supplies the value; it can be obtained with
 * {@code dig +short HTTPS <host>} or any DNS-over-HTTPS client.
 */
public interface EchConfigProvider {

    /**
     * @param host the server name that would otherwise be sent as a plaintext SNI.
     * @return the raw {@code ECHConfigList} (the base64 decoded {@code ech=} value), or null if the
     *         host publishes no ECHConfig, in which case a GREASE ECH is sent instead.
     */
    byte[] getEchConfigList(String host);

}
