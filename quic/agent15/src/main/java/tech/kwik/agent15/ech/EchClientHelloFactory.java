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

import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.ClientHello;

/**
 * Builds one of the two ClientHellos of an Encrypted Client Hello, so that
 * {@link EchClient} can produce both without knowing how either is put together.
 * <p>
 * They differ in three things and nothing else: the server name, the
 * "encrypted_client_hello" extension, and the random. Everything else - the cipher suites, the other
 * extensions, their order, the key shares - is the same in both, which is what RFC 9849 section 6.1
 * allows ("It MAY copy any other field from the ClientHelloInner except ClientHelloInner.random")
 * and what makes a dictated ClientHello work under ECH at all: the shape is described once and used
 * twice.
 */
@FunctionalInterface
public interface EchClientHelloFactory {

    /**
     * @param serverName             the real name for the ClientHelloInner, the ECHConfig's public
     *                               name for the ClientHelloOuter.
     * @param encryptedClientHello   the extension to send, replacing whatever the ClientHello would
     *                               otherwise carry in that slot - which for a browser profile is a
     *                               GREASE ECH, in exactly the position the real one belongs.
     * @param payloadCalculator      null for the ClientHelloInner; for the ClientHelloOuter, what
     *                               seals the inner into it once it has been serialized.
     */
    ClientHello create(String serverName, Extension encryptedClientHello, EchPayloadCalculator payloadCalculator);
}
