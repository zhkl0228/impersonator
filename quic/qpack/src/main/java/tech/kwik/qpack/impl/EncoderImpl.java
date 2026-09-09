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

import tech.kwik.qpack.Encoder;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static tech.kwik.qpack.impl.PrefixedInteger.insertPrefixedInteger;


public class EncoderImpl implements Encoder {

    public static final Charset HTTP_HEADER_CHARSET = Charset.forName("US-ASCII");

    private final Huffman huffman;
    private final StaticTable staticTable;
    private final List<AbstractMap.Entry<String, String>> dynamicTable;
    private final boolean useHuffmanEncoding;

    public EncoderImpl(boolean useHuffmanEncoding) {
        this.useHuffmanEncoding = useHuffmanEncoding;
        staticTable = StaticTable.getInstance();
        huffman = Huffman.getInstance();
        dynamicTable = new ArrayList<>();
    }

    /**
     * Compresses a set of headers into a QPack Header Block.
     * See https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5
     * @param headers
     * @return the created header block. Note that the underlying array will be larger than the number of bytes written in the buffer.
     * Use buffer.limit() to determine how many bytes to use.
     */
    @Override
    public ByteBuffer compressHeaders(List<Map.Entry<String, String>> headers) {
        // worst case estimate: 2 bytes for the blockprefix,
        // and for both strings: 6 bytes for the length (MAX_INT takes 6 bytes in prefixed-int format) + string length
        int estimatedSize = 2 + headers.stream().mapToInt(entry -> 6 + entry.getKey().length() + 6 + entry.getValue().length()).sum();
        ByteBuffer buffer = ByteBuffer.allocate(estimatedSize);

        insertHeaderBlockPrefix(buffer);

        headers.forEach(entry -> compressEntry(entry, buffer));

        buffer.limit(buffer.position());
        return buffer;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5.1
    private void insertHeaderBlockPrefix(ByteBuffer buffer) {
        buffer.put((byte) 0x00);
        buffer.put((byte) 0x00);
    }

    void compressEntry(Map.Entry<String, String> entry, ByteBuffer buffer) {
        TableEntry tableEntry = staticTable.findByNameAndValue(entry.getKey(), entry.getValue());
        if (tableEntry != null) {
            if (! tableEntry.isValueEmpty()) {
                assert tableEntry.getValue().equals(entry.getValue());
                insertIndexedHeaderField(tableEntry.getIndex(), buffer);
            }
            else {
                insertLiteralHeaderFieldWithNameReference(tableEntry.getIndex(), entry.getValue(), buffer);
            }
        }
        else {
            insertLiteralHeaderFieldWithoutNameReference(entry, buffer);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.2
    private void insertIndexedHeaderField(int index, ByteBuffer buffer) {
        insertPrefixedInteger(6, (byte) 0xc0, index, buffer);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.4
    private void insertLiteralHeaderFieldWithNameReference(int index, String value, ByteBuffer buffer) {
        insertPrefixedInteger(4, (byte) 0x50, index, buffer);
        byte[] valueBytes = value.getBytes(HTTP_HEADER_CHARSET);
        if (useHuffmanEncoding) {
            byte[] encodedBytes = huffman.encode(valueBytes);
            insertPrefixedInteger(7, (byte) 0x80, encodedBytes.length, buffer);
            buffer.put(encodedBytes);
        }
        else {
            insertPrefixedInteger(7, (byte) 0x00, valueBytes.length, buffer);
            buffer.put(valueBytes);
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.6
    private void insertLiteralHeaderFieldWithoutNameReference(Map.Entry<String, String> entry, ByteBuffer buffer) {
        byte[] keyBytes = entry.getKey().getBytes(HTTP_HEADER_CHARSET);
        if (useHuffmanEncoding) {
            byte[] encodedBytes = huffman.encode(keyBytes);
            insertPrefixedInteger(3, (byte) 0x28, encodedBytes.length, buffer);
            buffer.put(encodedBytes);
        }
        else {
            insertPrefixedInteger(3, (byte) 0x20, keyBytes.length, buffer);
            buffer.put(keyBytes);
        }
        byte[] valueBytes = entry.getValue().getBytes(HTTP_HEADER_CHARSET);
        if (useHuffmanEncoding) {
            byte[] encodedBytes = huffman.encode(valueBytes);
            insertPrefixedInteger(7, (byte) 0x80, encodedBytes.length, buffer);
            buffer.put(encodedBytes);
        }
        else {
            insertPrefixedInteger(7, (byte) 0x00, valueBytes.length, buffer);
            buffer.put(valueBytes);
        }
    }

}
