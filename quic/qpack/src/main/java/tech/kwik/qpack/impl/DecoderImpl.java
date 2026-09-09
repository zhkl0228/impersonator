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

import tech.kwik.qpack.Decoder;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static tech.kwik.qpack.impl.PrefixedInteger.parsePrefixedInteger;


public class DecoderImpl implements Decoder {

    private final Huffman huffman;
    private final StaticTable staticTable;
    private final List<AbstractMap.Entry<String, String>> dynamicTable;

    public DecoderImpl() {
        staticTable = StaticTable.getInstance();
        huffman = Huffman.getInstance();
        dynamicTable = new ArrayList<>();
    }

    public void decodeEncoderStream(InputStream inputStream) throws IOException {
        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream, 16);
        int instruction = pushbackInputStream.read();
        pushbackInputStream.unread(instruction);

        while (instruction >= 0) {  // EOF returns -1

            if ((instruction & 0x80) == 0x80) {
                parseInsertWithNameReference(pushbackInputStream);
            }
            else if ((instruction & 0xc0) == 0x40) {
                parseInsertWithoutNameReference(pushbackInputStream);
            }
            else {
                throw new NotYetImplementedException("Error: unknown instruction in encoder stream: " + instruction);
            }

            instruction = pushbackInputStream.read();
            pushbackInputStream.unread(instruction);
        }
    }

    @Override
    public List<Map.Entry<String, String>> decodeStream(InputStream inputStream) throws IOException {
        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream, 16);
        List<Map.Entry<String, String>> headers = new ArrayList<>();

        // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5.1
        // "Header Block Prefix"
        long requiredInsertCount = parsePrefixedInteger(8, pushbackInputStream);
        int deltaBase = (int) parsePrefixedInteger(7, pushbackInputStream);

        int instruction = pushbackInputStream.read();
        pushbackInputStream.unread(instruction);
        while (instruction >= 0) {  // EOF returns -1
            Map.Entry<String, String> entry = null;
            if ((instruction & 0x80) == 0x80) {
                entry = parseIndexedHeaderField(pushbackInputStream);
            }
            else if ((instruction & 0xc0) == 0x40) {
                entry = parseLiteralHeaderFieldWithNameReference(pushbackInputStream);
            }
            else if ((instruction & 0xe0) == 0x20) {
                entry = parseLiteralHeaderFieldWithoutNameReference(pushbackInputStream);
            }
            else {
                throw new NotYetImplementedException("Error: unknown instruction: " + instruction);
            }

            if (entry != null) {
                headers.add(entry);
            }
            instruction = pushbackInputStream.read();
            pushbackInputStream.unread(instruction);
        }

        return headers;
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.3.1
    void parseInsertWithNameReference(PushbackInputStream inputStream) throws IOException {
        byte first = read(inputStream);
        inputStream.unread(first);

        int index = (int) parsePrefixedInteger(6, inputStream);
        boolean referStatic = (first & 0x40) == 0x40;
        String name = referStatic? staticTable.lookupName(index): lookupDynamicTable(index).getKey();

        String value = parseStringValue(inputStream);
        addToTable(name, value);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.3.2
    void parseInsertWithoutNameReference(PushbackInputStream inputStream) throws IOException {
        String name = parseStringValue(5, inputStream);
        String value = parseStringValue(inputStream);
        addToTable(name, value);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5.2
    Map.Entry<String, String> parseIndexedHeaderField(PushbackInputStream inputStream) throws IOException {
        byte first = read(inputStream);
        inputStream.unread(first);
        boolean inStaticTable = (first & 0x40) == 0x40;
        int index = (int) parsePrefixedInteger(6, inputStream);

        if (inStaticTable) {
            return staticTable.lookupNameValue(index);
        }
        else {
            return lookupDynamicTable(index);
        }
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5.4
    Map.Entry<String, String> parseLiteralHeaderFieldWithNameReference(PushbackInputStream inputStream) throws IOException {
        byte first = read((inputStream));
        inputStream.unread(first);
        boolean inStaticTable = (first & 0x10) == 0x10;
        int nameIndex = (int) parsePrefixedInteger(4, inputStream);
        if (! inStaticTable) {
            throw new NotYetImplementedException("non static ref in parseLiteralHeaderFieldWithNameReference");
        }
        String name = inStaticTable? staticTable.lookupName(nameIndex): "<tbd>";

        String value = parseStringValue(inputStream);

        return new AbstractMap.SimpleEntry<>(name, value);
    }

    // https://tools.ietf.org/html/draft-ietf-quic-qpack-07#section-4.5.6
    Map.Entry<String, String> parseLiteralHeaderFieldWithoutNameReference(PushbackInputStream inputStream) throws IOException {
        String name = parseStringValue(3, inputStream);
        String value = parseStringValue(inputStream);
        return new AbstractMap.SimpleEntry<>(name, value);
    }

    Map.Entry<String, String> lookupDynamicTable(int index) {
        if (index < dynamicTable.size()) {
            return dynamicTable.get(index);
        }
        else {
            return null;
        }
    }

    private String parseStringValue(PushbackInputStream inputStream) throws IOException {
        byte firstByte = read(inputStream);
        inputStream.unread(firstByte);
        boolean huffmanEncoded = (firstByte & 0x80) == 0x80;
        int valueLength = (int) parsePrefixedInteger(7, inputStream);
        byte[] rawValue = new byte[valueLength];
        readExact(inputStream, rawValue);
        return huffmanEncoded? huffman.decode(rawValue): new String(rawValue, StandardCharsets.ISO_8859_1);
    }

    private String parseStringValue(int prefixLength, PushbackInputStream inputStream) throws IOException {
        int huffmanFlagMask;
        switch(prefixLength) {
            case 3:
                huffmanFlagMask = 0x08;
                break;
            case 5:
                huffmanFlagMask = 0x20;
                break;
            default:
                throw new NotYetImplementedException("no huffman flag mask for prefix " + prefixLength);
        }
        byte firstByte = read(inputStream);
        inputStream.unread(firstByte);
        boolean huffmanEncoded = (firstByte & huffmanFlagMask) == huffmanFlagMask;
        int length = (int) parsePrefixedInteger(prefixLength, inputStream);
        byte[] rawBytes = new byte[length];
        readExact(inputStream, rawBytes);
        return huffmanEncoded? huffman.decode(rawBytes): new String(rawBytes, StandardCharsets.ISO_8859_1);
    }

    private void addToTable(String name, String value) {
        dynamicTable.add(new AbstractMap.SimpleEntry<>(name, value));
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

    private void readExact(InputStream stream, byte[] data) throws IOException {
        int read = stream.readNBytes(data, 0, data.length);
        if (read != data.length) {
            throw new EOFException();
        }
    }
}
