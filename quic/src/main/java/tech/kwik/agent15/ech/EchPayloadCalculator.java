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
 * Seals the EncodedClientHelloInner once the ClientHelloOuter it is bound to has been serialized.
 * <p>
 * RFC 9849 section 5.2 makes the serialized ClientHelloOuter - with the "encrypted_client_hello"
 * payload zeroed - the additional data of the HPKE seal, so the payload can only be computed after
 * the message has been laid out. {@code ClientHello} therefore serializes once with the zeros in
 * place, calls this, and writes the result back over them; the two have the same length, so no
 * length prefix changes.
 */
@FunctionalInterface
public interface EchPayloadCalculator {

    /**
     * @param clientHelloOuterAad the serialized ClientHelloOuter with a zeroed payload, without the
     *                            four byte handshake header.
     * @return the sealed EncodedClientHelloInner, of exactly the length of the zeros it replaces.
     */
    byte[] calculatePayload(byte[] clientHelloOuterAad);
}
