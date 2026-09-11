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
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator): the string literals the three
 * instructions carry are written by one method, and Huffman coding is used only where it makes the
 * string shorter; see quic/qpack/UPSTREAM.md.
 */
package tech.kwik.qpack.impl;

import tech.kwik.qpack.Encoder;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static tech.kwik.qpack.impl.PrefixedInteger.insertPrefixedInteger;


public class EncoderImpl implements Encoder {

    public static final Charset HTTP_HEADER_CHARSET = StandardCharsets.US_ASCII;

    private final Huffman huffman;
    private final StaticTable staticTable;
    private final boolean useHuffmanEncoding;

    public EncoderImpl(boolean useHuffmanEncoding) {
        this.useHuffmanEncoding = useHuffmanEncoding;
        staticTable = StaticTable.getInstance();
        huffman = Huffman.getInstance();
    }

    /**
     * Compresses a set of headers into a QPack Header Block.
     * See <a href="https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5">draft-ietf-quic-qpack-07#section-4.5</a>
     * @return the created header block. Note that the underlying array will be larger than the number of bytes written in the buffer.
     * Use buffer.limit() to determine how many bytes to use.
     */
    @Override
    public ByteBuffer compressHeaders(List<Map.Entry<String, String>> headers) {
        // worst case estimate: 2 bytes for the blockprefix,
        // and for both strings: 6 bytes for the length (MAX_INT takes 6 bytes in prefixed-int format) + string length.
        // The string length is the bound only because insertStringLiteral never writes more bytes than the string has;
        // Huffman coding that is taken unconditionally can write more, and did overflow this buffer.
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
        insertStringLiteral(7, (byte) 0x00, value, buffer);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.6
    private void insertLiteralHeaderFieldWithoutNameReference(Map.Entry<String, String> entry, ByteBuffer buffer) {
        insertStringLiteral(3, (byte) 0x20, entry.getKey(), buffer);
        insertStringLiteral(7, (byte) 0x00, entry.getValue(), buffer);
    }

    /**
     * See <a href="https://www.rfc-editor.org/rfc/rfc9204.html#section-4.1.2">RFC 9204 section 4.1.2</a>:
     * "The prefix used for the string length and the position of the H bit vary based on the instruction
     *  being encoded."
     * H sits immediately above the length's prefix, so for an N bit prefix it is bit N - which is the
     * whole of the difference between the three literals this encoder writes.
     * <p>
     * Huffman coding is taken only where it wins. The code in RFC 7541 appendix B is per symbol and
     * spends 12 to 15 bits on symbols a header field really does contain - '#', '$', '@', '[', ']',
     * '^', '{', '}' - so a value made of them codes to more bytes than it has, and asking for Huffman
     * got a section larger than the buffer compressHeaders sized from the plain lengths: a
     * BufferOverflowException out of the encoder itself.
     * <p>
     * A tie is not a win, so a string that codes to the same number of bytes goes out plain - which is
     * also what keeps an empty string from going out as H set over no bytes at all.
     *
     * @param prefixLength the number of bits the length has in the first byte
     * @param pattern      the instruction, in the bits above the prefix, with H not set
     */
    private void insertStringLiteral(int prefixLength, byte pattern, String value, ByteBuffer buffer) {
        byte[] bytes = value.getBytes(HTTP_HEADER_CHARSET);
        if (useHuffmanEncoding) {
            byte[] encoded = huffman.encode(bytes);
            if (encoded.length < bytes.length) {
                bytes = encoded;
                pattern |= (byte) (1 << prefixLength);
            }
        }
        insertPrefixedInteger(prefixLength, pattern, bytes.length, buffer);
        buffer.put(bytes);
    }

}
