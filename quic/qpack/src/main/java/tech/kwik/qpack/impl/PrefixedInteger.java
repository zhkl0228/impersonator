/*
 * Copyright © 2026 Peter Doornbosch
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

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.1
 * "The prefixed integer from Section 5.1 of [RFC7541] is used heavily throughout this document. The format from
 *  [RFC7541] is used unmodified. Note, however, that QPACK uses some prefix sizes not actually used in HPACK.
 *  QPACK implementations MUST be able to decode integers up to and including 62 bits long."
 * See also https://tools.ietf.org/html/rfc7541#section-5.1
 */
/*
 * Modified for impersonator (https://github.com/zhkl0228/impersonator): added writePrefixedInteger,
 * and fixed the continuation boundary and the 32 bit shift; see quic/qpack/UPSTREAM.md.
 */
public class PrefixedInteger {

    static void insertPrefixedInteger(int prefixLength, byte prefix, int value, ByteBuffer buffer) {
        int maxPrefix = (int) (Math.pow(2, prefixLength) - 1);
        if (value < maxPrefix) {
            buffer.put((byte) (prefix | value));
        } else {
            buffer.put((byte) (prefix | maxPrefix));
            int remainder = value - maxPrefix;
            while (remainder >= 128) {
                byte next = (byte) ((remainder % 128) | 0x80);
                buffer.put(next);
                remainder = remainder / 128;
            }
            buffer.put((byte) remainder);
        }
    }

    /**
     * Writes a prefixed integer, the high bits of the first byte being the instruction it belongs to.
     *
     * @param prefixBits the instruction pattern, in the bits above the prefix
     */
    static void writePrefixedInteger(int prefixLength, byte prefixBits, long value, OutputStream output) throws IOException {
        int maxPrefix = (1 << prefixLength) - 1;
        if (value < maxPrefix) {
            output.write((prefixBits & 0xff) | (int) value);
        }
        else {
            output.write((prefixBits & 0xff) | maxPrefix);
            long remainder = value - maxPrefix;
            while (remainder >= 128) {
                output.write((int) ((remainder % 128) | 0x80));
                remainder /= 128;
            }
            output.write((int) remainder);
        }
    }

    static long parsePrefixedInteger(int prefixLength, InputStream input) throws IOException {
        int maxPrefix = (int) (Math.pow(2, prefixLength) - 1);
        int initialValue = read(input) & maxPrefix;
        if (initialValue < maxPrefix) {
            return initialValue;
        }

        long value = initialValue;
        int factor = 0;
        byte next;
        do {
            next = read(input);
            value += ((long) (next & 0x7f)) << factor;
            factor += 7;
        }
        while ((next & 0x80) == 0x80);

        return value;
    }

    static private byte read(InputStream stream) throws IOException {
        int value = stream.read();
        if (value == -1) {
            throw new EOFException();
        }
        else {
            return (byte) value;
        }
    }
}
