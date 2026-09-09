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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.extension.Extension;

import java.util.List;

/**
 * Dictates the shape of the ClientHello, so that it can be made to look like some other client's
 * rather than like agent15's.
 * <p>
 * Without one, agent15 sends what it needs and nothing more: one cipher suite, one key share, eight
 * extensions in a fixed order. That is a fingerprint of its own - JA4 reads the cipher list, the
 * extension types and the signature algorithms straight out of the ClientHello - so anything trying
 * to pass for a browser has to be able to say exactly what goes in and in what order, including
 * extensions agent15 has no model of and GREASE values it would never invent.
 * <p>
 * The engine still owns what only it can know: the client random, and the private keys behind the
 * key shares. Everything else comes from here.
 *
 * @see tech.kwik.agent15.extension.RawExtension
 */
public interface ClientHelloSpec {

    /**
     * The cipher suite values in the order they go on the wire, GREASE included. The engine still
     * negotiates only the suites it implements: a server that picks one of the others is refused,
     * the same as one that picks a suite that was never offered.
     */
    int[] getCipherSuites();

    /**
     * The named groups to send a key share for, in order. The engine asks
     * {@link #generateEphemeral(int)} for each one, so a group agent15 has no implementation of -
     * X25519MLKEM768, say - is offered as readily as one it does.
     */
    int[] getKeyShareGroups();

    /**
     * The ephemeral public value to put in the key_share entry for {@code namedGroup}, and to keep
     * whatever private state answering {@link #calculateSharedSecret} will need.
     */
    byte[] generateEphemeral(int namedGroup);

    /**
     * @param namedGroup the group the server echoed in its key_share.
     * @param peerValue  the server's key exchange value, as it arrived.
     * @return the shared secret, which goes into the key schedule as is.
     */
    byte[] calculateSharedSecret(int namedGroup, byte[] peerValue);

    /**
     * Every extension of the ClientHello, in the order they go on the wire, key_share included.
     *
     * @param serverName  the host being connected to, for the extensions that name it.
     * @param keyShare    the key_share extension built from {@link #generateEphemeral(int)}, offered
     *                    here so that the caller can place it rather than have it appended.
     * @param engineExtensions the extensions the caller of the engine added, ALPN and QUIC's
     *                    transport parameters among them. They have to appear in the result, since
     *                    the handshake will not work without them, but where is up to the spec.
     */
    List<Extension> getExtensions(String serverName, Extension keyShare, List<Extension> engineExtensions);

}
