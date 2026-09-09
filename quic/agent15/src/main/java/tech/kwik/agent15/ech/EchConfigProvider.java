/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator), which adds
 * Encrypted Client Hello (RFC 9849) to Agent15, an implementation of TLS 1.3 in Java.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.ech;

/**
 * Supplies the ECHConfigList to offer for a given server name, and hears about it when a server
 * rejects what it supplied.
 * <p>
 * An ECHConfigList belongs to a host rather than to a connection, so this is normally one object
 * shared by every connection; install it with
 * {@link tech.kwik.agent15.engine.TlsClientEngineFactory#setDefaultEchConfigProvider}, because a
 * QUIC implementation creates its TLS engines itself.
 */
public interface EchConfigProvider {

    /**
     * @param serverName the server name that would otherwise be sent as a plaintext SNI.
     * @return the raw {@code ECHConfigList} (the decoded {@code ech} value of the host's DNS HTTPS
     *         record, RFC 9460), or null to send a plain ClientHello with a visible SNI.
     */
    byte[] getEchConfigList(String serverName);

    /**
     * Called once per connection on which the server rejected the offered ECHConfig, just before
     * the handshake is failed with {@link EchRejectedException}. The real server name went out in
     * the clear on this connection, and the rejection is authenticated: it is only reported after
     * the certificate presented for {@link EchRejectedException#getPublicName()} has been verified.
     * <p>
     * This is the hook for RFC 9849 section 6.1.6: remember
     * {@link EchRejectedException#getRetryConfigs() the retry configs} and offer them on the next
     * connection, or disable ECH for this host when there are none. The engine itself never
     * retries.
     *
     * @param rejection the rejection that is about to be thrown.
     */
    void echRejected(EchRejectedException rejection);

}
