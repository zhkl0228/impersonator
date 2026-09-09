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

import java.util.List;

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
public interface EchClientHelloFactory {

    /**
     * The extensions for one of the two messages. The list is drawn once per connection and the same
     * one is returned every time, with only two slots substituted, so that the inner and the outer
     * agree on which extensions they carry and in what order - which is what RFC 9849 section 5.1
     * needs before either can be compressed against the other.
     *
     * @param serverName           the real name for the inner, the ECHConfig's public name for the outer.
     * @param encryptedClientHello the extension to put in the "encrypted_client_hello" slot, replacing
     *                             whatever the ClientHello would otherwise carry there.
     */
    List<Extension> createExtensions(String serverName, Extension encryptedClientHello);

    /**
     * @param clientRandom      the 32 byte random; the ClientHelloInner and its encoded form share one,
     *                          the ClientHelloOuter has its own.
     * @param payloadCalculator null except for the ClientHelloOuter, where it seals the inner in once
     *                          the message has been serialized.
     */
    ClientHello createClientHello(byte[] clientRandom, List<Extension> extensions,
                                  EchPayloadCalculator payloadCalculator);
}
