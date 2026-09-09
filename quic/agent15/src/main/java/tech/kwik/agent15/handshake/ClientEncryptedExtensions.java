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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.TlsConstants;

import java.nio.ByteBuffer;

/**
 * The client's EncryptedExtensions message, which exists for one extension: Application-Layer
 * Protocol Settings (draft-vvv-tls-alps).
 * <p>
 * TLS 1.3 has the server send EncryptedExtensions and the client never does, so this is the one place
 * where handshake type 8 travels the other way. When the server accepts ALPS - by echoing
 * "application_settings" in its own EncryptedExtensions - it then waits for this message, and a
 * client that advertised the extension and does not send it fails the handshake. Google does exactly
 * that, with "got type 20, wanted type 8": the Finished arriving where this should have been.
 * <p>
 * The layout is BoringSSL's {@code do_send_client_encrypted_extensions}: an extension block holding
 * the one extension, whose body is the client's settings and nothing else. It goes into the transcript
 * like every other handshake message, before the client's Certificate and Finished.
 */
public class ClientEncryptedExtensions extends HandshakeMessage {

    private final byte[] raw;

    /**
     * @param extensionType the "application_settings" codepoint the ClientHello used; the answer has
     *                      to be in the same one it was asked in, and there are two in use
     * @param settings      the client's settings for the negotiated protocol, which may be empty -
     *                      for HTTP/3 it is: QUICHE's client passes {@code settings_len = 0}, so
     *                      everything ALPS carries on that protocol travels the other way
     */
    public ClientEncryptedExtensions(int extensionType, byte[] settings) {
        int extensionsLength = 2 + 2 + settings.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 2 + extensionsLength);
        buffer.putInt((TlsConstants.HandshakeType.encrypted_extensions.value << 24) | (2 + extensionsLength));
        buffer.putShort((short) extensionsLength);
        buffer.putShort((short) extensionType);
        buffer.putShort((short) settings.length);
        buffer.put(settings);
        raw = buffer.array();
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.encrypted_extensions;
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }
}
