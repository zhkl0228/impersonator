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
 * An Encrypted Client Hello could not be built, so no ClientHello was sent at all.
 * <p>
 * Unchecked on purpose: it is thrown out of {@code TlsClientEngine.startHandshake}, and a QUIC
 * implementation is entitled to assume that starting a handshake does not fail - kwik's
 * {@code QuicClientConnectionImpl.startHandshake} discards the declared {@code IOException} with
 * the comment that it cannot happen. A checked exception would therefore be swallowed and the
 * connection would hang until it timed out, with nothing in the log.
 * <p>
 * Every message names the ECHConfig it came from, because the usual cause is a host publishing an
 * ECHConfigList this implementation cannot use.
 */
public class EchException extends RuntimeException {

    public EchException(String message) {
        super(message);
    }

    public EchException(String message, Throwable cause) {
        super(message, cause);
    }
}
