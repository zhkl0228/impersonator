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
package tech.kwik.agent15.util;

import java.nio.ByteBuffer;
import java.util.regex.Pattern;

public class ByteUtils {

    public static final Pattern HEXADECIMAL_PATTERN = Pattern.compile("\\p{XDigit}+");

    public static String bytesToHex(byte[] data, int length) {
        String digits = "0123456789abcdef";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String bytesToHex(byte[] data) {
        return bytesToHex(data, data.length);
    }

    public static String bytesToHex(byte[] data, int offset, int length) {
        String digits = "0123456789abcdef";
        StringBuffer buffer = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[offset+i] & 0xff;

            buffer.append(digits.charAt(v >> 4));
            buffer.append(digits.charAt(v & 0xf));
        }

        return buffer.toString();
    }

    public static String byteToHexBlock(byte[] data) {
        return byteToHexBlock(data, data.length);
    }

    public static String byteToHexBlock(byte[] data, int length) {
        String result = "";
        for (int i = 0; i < length; ) {
            result += (String.format("%02x ", data[i]));
            i++;
            if (i < data.length)
            if (i % 16 == 0)
                result += "\n";
            else if (i % 8 == 0)
                result += " ";
        }
        return result;
    }

    public static String byteToHexBlock(ByteBuffer data, int start, int size) {
        int initialPosition = data.position();
        data.position(start);
        byte[] dataBytes = new byte[size];
        data.get(dataBytes);
        data.position(initialPosition);
        return byteToHexBlock(dataBytes);
    }

    public static byte[] hexToBytes(String hex) {
        hex = hex.replace(" ", "");
        if (! HEXADECIMAL_PATTERN.matcher(hex).matches()) {
            throw new IllegalArgumentException("Input should be hexadecimal string");
        }
        int length = hex.length();
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character
                    .digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
