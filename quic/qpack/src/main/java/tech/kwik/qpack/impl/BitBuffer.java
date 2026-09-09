/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Flupke, a HTTP3 Java library.
 *
 * Flupke is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Flupke is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.qpack.impl;

import java.nio.ByteBuffer;

public class BitBuffer {

    private final ByteBuffer data;

    private int head;
    private int bitsInHead;
    private int unsetInHead;

    public BitBuffer(byte[] data) {
        this.data = ByteBuffer.wrap(data);
        for (int i = 0; i < 4; i++) {
            if (i < data.length) {
                head = (head << 8) | (this.data.get() & 0x000000ff);
                bitsInHead += 8;
            }
            else {
                head = (head << 8) | 0x000000ff;
            }
        }
    }

    byte peek() {
        return (byte) ((head & 0xff000000) >> 24);
    }

    public void shift(int size) {
        if (unsetInHead + size >= 8) {
            // Shift that much so exactly 8 bits are not set
            head = head << (8 - unsetInHead);
            // Move in next byte (if any, otherwise move in EOS)
            if (data.remaining() > 0) {
                head = head | (data.get() & 0x000000ff);
                bitsInHead += 8;
            }
            else {
                head = head | 0x000000ff;
            }
            // Shift the rest
            int remaining = size - (8 - unsetInHead);
            head = head << remaining;
            bitsInHead -= size;
            unsetInHead = remaining;
        }
        else {
            head = head << size;
            bitsInHead -= size;
            unsetInHead += size;
        }
    }

    public boolean hasRemaining() {
        return bitsInHead > 0;
    }

    public int remaining() {
        return bitsInHead > 0? bitsInHead: 0;
    }
}
