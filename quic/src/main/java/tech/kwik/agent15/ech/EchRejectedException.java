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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.ErrorAlert;

/**
 * Thrown when Encrypted Client Hello was offered and the server did not accept it, so the real
 * server name travelled in the clear. RFC 9849 section 6.1.6.
 * <p>
 * The handshake is run to the end first: the certificate chain is validated, its CertificateVerify
 * is checked, and it must name {@link #getPublicName()}. Only then is this thrown, so that the
 * rejection is authenticated - otherwise an on-path attacker could force one and choose the
 * {@link #getRetryConfigs() retry configs} the caller remembers for its next connection. The
 * connection is never reported as successful, because it was authenticated for the public name and
 * not for the origin.
 * <p>
 * Retrying is the caller's decision; see {@link EchConfigProvider#echRejected}.
 */
public class EchRejectedException extends ErrorAlert {

    private final String serverName;
    private final String publicName;
    private final byte[] retryConfigs;

    public EchRejectedException(String serverName, String publicName, byte[] retryConfigs, String message) {
        super(message, TlsConstants.AlertDescription.ech_required);

        this.serverName = serverName;
        this.publicName = publicName;
        this.retryConfigs = retryConfigs;
    }

    /** The real server name, the one the ClientHelloInner carried and the connection was for. */
    public String getServerName() {
        return serverName;
    }

    /**
     * The {@code ECHConfig.contents.public_name} that was sent as the ClientHelloOuter's server
     * name, and that the server's certificate was verified against.
     */
    public String getPublicName() {
        return publicName;
    }

    /**
     * The raw ECHConfigList the server wants to be retried with, or null if it sent none, which per
     * section 6.1.6 means Encrypted Client Hello is securely disabled for this server.
     */
    public byte[] getRetryConfigs() {
        return retryConfigs;
    }
}
