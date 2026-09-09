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

import java.nio.ByteBuffer;

public class UnknownExtension extends Extension {

    private byte[] data;
    private int type;

    public UnknownExtension parse(ByteBuffer buffer) throws DecodeErrorException {
        if (buffer.remaining() < 4) {
            throw new DecodeErrorException("Extension must be at least 4 bytes long");
        }

        buffer.mark();
        type = buffer.getShort() & 0xffff;
        int length = buffer.getShort() & 0xffff;
        if (buffer.remaining() < length) {
            throw new DecodeErrorException("Invalid extension length");
        }
        buffer.reset();
        data = new byte[4 + length];
        buffer.get(data);

        return this;
    }

    public byte[] getData() {
        return data;
    }

    @Override
    public int getType() {
        return type;
    }

    @Override
    public byte[] getBytes() {
        return new byte[0];
    }
}
