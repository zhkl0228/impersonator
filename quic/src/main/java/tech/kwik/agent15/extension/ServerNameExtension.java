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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/**
 * TLS server name extension: RFC 6066
 * https://tools.ietf.org/html/rfc6066#section-3
 */
public class ServerNameExtension extends Extension {

    private String serverName;

    public ServerNameExtension(String serverName) {
        this.serverName = serverName;
    }

    public ServerNameExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.server_name, 0);
        if (extensionDataLength > 0) {
            if (extensionDataLength < 2) {
                throw new DecodeErrorException("incorrect extension length");
            }
            int serverNameListLength = buffer.getShort() & 0xffff;
            if (extensionDataLength != serverNameListLength + 2) {
                throw new DecodeErrorException("inconsistent length");
            }

            int remainingListLength = serverNameListLength;
            while (remainingListLength > 0) {
                int read = parseServerName(buffer);
                remainingListLength -= read;
            }
            if (remainingListLength < 0) {
                throw new DecodeErrorException("inconsistent length");
            }
        }
        else {
            // https://tools.ietf.org/html/rfc6066#section-3
            // " A server that receives a client hello containing the "server_name" extension (...). In this event,
            // the server SHALL include an extension of type "server_name" in the (extended) server hello.
            // The "extension_data" field of this extension SHALL be empty."
            serverName = null;
        }
    }

    private int parseServerName(ByteBuffer buffer) throws DecodeErrorException {
        checkMinRemaining(buffer,1);
        int nameType = buffer.get();
        switch (nameType) {
            case 0:
                // host_name
                checkMinRemaining(buffer,2);
                int hostNameLength = buffer.getShort() & 0xffff;
                checkMinRemaining(buffer, hostNameLength);
                byte[] hostNameBytes = new byte[hostNameLength];
                buffer.get(hostNameBytes);
                // "The hostname is represented as a byte string using ASCII encoding without a trailing dot. "
                serverName = new String(hostNameBytes, Charset.forName("ASCII"));
                return 1 + 2 + hostNameLength;
            default:
                // Unsupported type, RFC 6066 only defines hostname
                // https://datatracker.ietf.org/doc/html/rfc6066#section-3
                // "For backward compatibility, all future data structures associated with new NameTypes MUST begin with
                //  a 16-bit length field. "
                checkMinRemaining(buffer,2);
                int dataLength = buffer.getShort() & 0xffff;
                checkMinRemaining(buffer,dataLength);
                if (dataLength > buffer.remaining()) {
                    throw new DecodeErrorException("extension underflow");
                }
                buffer.get(new byte[dataLength]);
                return 1 + 2 + dataLength;
        }
    }

    @Override
    public byte[] getBytes() {
        short hostnameLength = (short) serverName.length();
        short extensionLength = (short) (hostnameLength + 2 + 1 + 2);

        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.server_name.value);
        buffer.putShort(extensionLength);  // Extension data length (in bytes)

        // https://tools.ietf.org/html/rfc6066#section-3
        buffer.putShort((short) (hostnameLength + 1 + 2));  // Length of server_name_list
        buffer.put((byte) 0x00);  // list entry is type 0x00 "DNS hostname"
        buffer.putShort(hostnameLength);  // Length of hostname
        buffer.put(serverName.getBytes(Charset.forName("ASCII")));

        return buffer.array();
    }

    public String getHostName() {
        return serverName;
    }

    private void checkMinRemaining(Buffer buffer, int min) throws DecodeErrorException {
        if (buffer.remaining() < min) {
            throw new DecodeErrorException("extension underflow");
        }

    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.server_name.value;
    }
}
