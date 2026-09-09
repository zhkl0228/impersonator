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
package tech.kwik.agent15.extension;

import java.nio.ByteBuffer;

/**
 * An extension this implementation has no model of, carried as the bytes it was given.
 * <p>
 * It exists so that a caller can put an extension in the ClientHello that agent15 knows nothing
 * about - "application_settings", "compress_certificate", "ec_point_formats", a GREASE value - which
 * is what impersonating a browser's ClientHello needs. agent15 never reads these; it only has to
 * write them in the right place, byte for byte.
 * <p>
 * Distinct from {@link UnknownExtension}, which is what the <em>parser</em> produces for an
 * extension it received and did not recognize, and whose {@code getBytes()} returns nothing.
 */
public class RawExtension extends Extension {

    private final int type;
    private final byte[] extensionData;

    /**
     * @param type          the extension type, 0 to 65535.
     * @param extensionData the extension_data, without the type and length prefix.
     */
    public RawExtension(int type, byte[] extensionData) {
        if (type < 0 || type > 0xffff) {
            throw new IllegalArgumentException("extension type out of range: " + type);
        }
        if (extensionData.length > 0xffff) {
            throw new IllegalArgumentException("extension " + type + " is " + extensionData.length
                    + " bytes, which does not fit a uint16 length");
        }
        this.type = type;
        this.extensionData = extensionData;
    }

    @Override
    public int getType() {
        return type;
    }

    /** The extension_data, without the type and length prefix. */
    public byte[] getExtensionData() {
        return extensionData;
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionData.length);
        buffer.putShort((short) type);
        buffer.putShort((short) extensionData.length);
        buffer.put(extensionData);
        return buffer.array();
    }

    @Override
    public String toString() {
        return "RawExtension[" + type + ", " + extensionData.length + " bytes]";
    }
}
