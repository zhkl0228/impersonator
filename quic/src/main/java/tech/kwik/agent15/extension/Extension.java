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

import java.nio.ByteBuffer;

/**
 * A TLS Extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2
 */
public abstract class Extension {

    protected int parseExtensionHeader(ByteBuffer buffer, TlsConstants.ExtensionType expectedType, int minimumExtensionSize) throws DecodeErrorException {
        return parseExtensionHeader(buffer, expectedType.value, minimumExtensionSize);
    }

    protected int parseExtensionHeader(ByteBuffer buffer, int expectedType, int minimumExtensionSize) throws DecodeErrorException {
        if (buffer.limit() - buffer.position() < 4) {
            throw new DecodeErrorException("extension underflow");
        }
        int extensionType = buffer.getShort() & 0xffff;
        if (extensionType != expectedType) {
            throw new IllegalStateException();  // i.e. programming error
        }
        int extensionDataLength = buffer.getShort() & 0xffff;
        if (extensionDataLength < minimumExtensionSize) {
            throw new DecodeErrorException(getClass().getSimpleName() + " can't be less than " + minimumExtensionSize + " bytes");
        }
        if (buffer.limit() - buffer.position() < extensionDataLength) {
            throw new DecodeErrorException("extension underflow");
        }
        return extensionDataLength;
    }

    /**
     * @return the extension type, as defined in https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2
     */
    public abstract int getType();

    public abstract byte[] getBytes();
}
