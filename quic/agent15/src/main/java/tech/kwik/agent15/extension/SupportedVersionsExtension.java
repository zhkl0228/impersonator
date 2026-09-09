/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.extension;

import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;

import java.nio.ByteBuffer;

/**
 * The TLS supported versions extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.1
 */
public class SupportedVersionsExtension extends Extension {

    private final TlsConstants.HandshakeType handshakeType;
    private short tlsVersion;

    public SupportedVersionsExtension(TlsConstants.HandshakeType handshakeType) {
        this.handshakeType = handshakeType;
        tlsVersion = 0x0304;
    }

    public SupportedVersionsExtension(ByteBuffer buffer, TlsConstants.HandshakeType handshakeType) throws TlsProtocolException {
        this.handshakeType = handshakeType;
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.supported_versions, 2);

        if (handshakeType == TlsConstants.HandshakeType.client_hello) {
            int versionsLength = buffer.get() & 0xff;
            if (versionsLength % 2 == 0 && extensionDataLength == versionsLength + 1) {
                for (int i = 0; i < versionsLength; i += 2) {
                    short version = buffer.getShort();
                    // This implementation only supports TLS 1.3, so search for that version.
                    if (version == 0x0304)  {
                        tlsVersion = version;
                    }
                }
            }
            else {
                throw new DecodeErrorException("invalid versions length");
            }
        }
        else if (handshakeType == TlsConstants.HandshakeType.server_hello) {
            if (extensionDataLength != 2) {
                throw new DecodeErrorException("Incorrect extension length");
            }
            tlsVersion = buffer.getShort();
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(handshakeType.equals(TlsConstants.HandshakeType.client_hello)? 7: 6);
        buffer.putShort(TlsConstants.ExtensionType.supported_versions.value);

        if (handshakeType.equals(TlsConstants.HandshakeType.client_hello)) {
            buffer.putShort((short) 3);  // Extension data length (in bytes)
            buffer.put((byte) 0x02);     // TLS versions bytes
            buffer.put(new byte[] { (byte) 0x03, (byte) 0x04 });  // TLS 1.3
        }
        else {
            buffer.putShort((short) 2);  // Extension data length (in bytes)
            buffer.put(new byte[] { (byte) 0x03, (byte) 0x04 });  // TLS 1.3
        }

        return buffer.array();
    }

    public short getTlsVersion() {
        return tlsVersion;
    }

    public boolean containsTls13() {
        return tlsVersion == 0x0304;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.supported_versions.value;
    }
}
