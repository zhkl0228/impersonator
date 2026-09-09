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

import java.nio.ByteBuffer;

/**
 * TLS Early Data Indication extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.10
 */
public class EarlyDataExtension extends Extension {

    private Long maxEarlyDataSize;

    public EarlyDataExtension() {
    }

    public EarlyDataExtension(long maxEarlyDataSize) {
        this.maxEarlyDataSize = maxEarlyDataSize;
    }

    public EarlyDataExtension(ByteBuffer buffer, TlsConstants.HandshakeType context) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.early_data.value, 0);

        // Only when used in New Session Ticket (message), the EarlyDataIndication value is non-empty.
        if (context == TlsConstants.HandshakeType.new_session_ticket) {
            if (extensionDataLength == 4) {
                maxEarlyDataSize = buffer.getInt() & 0xffffffffL;
            }
            else {
                throw new DecodeErrorException("invalid extension data length");
            }
        }
        else if (extensionDataLength != 0) {
            throw new DecodeErrorException("invalid extension data length");
        }
    }

    @Override
    public byte[] getBytes() {
        int extensionDataLength = maxEarlyDataSize == null? 0: 4;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionDataLength);
        buffer.putShort(TlsConstants.ExtensionType.early_data.value);
        buffer.putShort((short) extensionDataLength);
        if (maxEarlyDataSize != null) {
            buffer.putInt((int) maxEarlyDataSize.longValue());
        }
        return buffer.array();
    }

    public long getMaxEarlyDataSize() {
        return maxEarlyDataSize;
    }

    @Override
    public String toString() {
        return "EarlyDataExtension " + (maxEarlyDataSize == null? "(empty)": "[" + maxEarlyDataSize + "]");
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.early_data.value;
    }
}
