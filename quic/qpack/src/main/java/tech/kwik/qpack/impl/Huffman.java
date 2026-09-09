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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Encodes and decodes Huffman code as specified by https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B
 */
public class Huffman {

    static private volatile Huffman instance = null;
    private final Decoder decoder;
    private final Encoder encoder;

    public static Huffman getInstance() {
        return Holder.INSTANCE;
    }

    private static class Holder {
        private static final Huffman INSTANCE = new Huffman();
    }

    private Huffman() {
        List<SymbolCodeEntry> huffmanCode = readHuffmanCodeFromResourceFile();
        decoder = new Decoder(huffmanCode);
        encoder = new Encoder(huffmanCode);
    }

    /**
     * Decodes a string of Huffman encoded bytes.
     * @param bytes
     * @return
     */
    public String decode(byte[] bytes) {
        return decoder.decode(bytes);
    }

    public byte[] encode(String string) {
        return encode(string.getBytes(StandardCharsets.ISO_8859_1));
    }

    public byte[] encode(byte[] string) {
        return encoder.encode(string);
    }

    private List<SymbolCodeEntry> readHuffmanCodeFromResourceFile() {
        InputStream resourceAsStream = this.getClass().getResourceAsStream("huffmancode.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(resourceAsStream));
        List<SymbolCodeEntry> codes = reader.lines()
                .dropWhile(line -> line.startsWith("#"))
                .map(line -> extractSymbolCodeEntry(line))
                .collect(Collectors.toList());
        return codes;
    }

    protected SymbolCodeEntry extractSymbolCodeEntry(String line) {
        String trimmedLine = line.trim();
        // Typical line:
        // '@' ( 64)  |11111111|11010                             1ffa  [13]
        //                                   (     64     )               |11111111|11010       1ffa                      [     13       ]
        Pattern pattern = Pattern.compile("\\(\\s*(\\d+)\\)" + "\\s+" + "([10|]+)" + "\\s+" + "([0-9a-f]+)" + "\\s+" + "\\[\\s*([0-9]+)\\]");
        Matcher matcher = pattern.matcher(trimmedLine);
        if (matcher.find()) {
            return new SymbolCodeEntry(
                    Integer.parseInt(matcher.group(1)),      // symbol (as integer)
                    matcher.group(2).replaceAll("\\|", ""),  // code as bits
                    Integer.parseInt(matcher.group(3), 16),  // code as hex
                    Integer.parseInt(matcher.group(4)));     // code length in bits
        }
        else {
            return null;
        }
    }

    /*
     * Represents a row in the Huffman code table as defined by https://datatracker.ietf.org/doc/html/rfc7541#appendix-B.
     */
    protected static class SymbolCodeEntry {
        /**  The symbol to be represented.  It is the decimal value of an octet. */
        public int symbol;
        /** The Huffman code for the symbol represented as a base-2 integer, aligned on the most significant bit (MSB). */
        public String asBits;
        /** The Huffman code for the symbol, represented as an integer, aligned on the least significant bit (LSB). */
        public int asInt;
        /** The number of bits for the code representing the symbol. */
        public int length;

        public SymbolCodeEntry(int symbol, String asBits, int asInt, int length) {
            if (!(asBits.length() == length)) {
                throw new IllegalArgumentException("Length of bit string does not match given length");
            }
            this.symbol = symbol;
            this.asBits = asBits;
            this.asInt = asInt;
            this.length = length;
        }
    }

    /**
     * Decoder for Huffman code as specified by https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B.
     * The decoding is implemented by nested lookup tables, where each lookup key is 8 bits. As the given Huffman code
     * has a maximum code length of 30 bits, the maximum nesting is 4 levels.
     * For example, the code for '\n' (decimal 10) is |11111111|11111111|11111111|111100, this requires four lookups: the
     * 1st, 2nd and 3rd point to the table that contains an entry for 0b111100xx.
     * As most codes are not an exact multiple of 8, the lookup must take into account the "don't care" bits. To simplify
     * the lookup, all values for the don't cares are included in the table.
     * For example, the code for '%' is 0b010101 (6 bits), and the table contains 4 entries (0b01010100, 0b01010101,
     * 0b01010110, 0b01010111), all pointing to the same table entry for '%'.
     */
    private static class Decoder {

        private static final int KEY_SIZE = 8;
        private static final int TABLE_SIZE = (int) Math.pow(2, KEY_SIZE);
        private final TableEntry[] lookupTable = new TableEntry[TABLE_SIZE];

        public Decoder(List<SymbolCodeEntry> codes) {
            codes.stream().forEach(code -> addToLookupTable(lookupTable, code.asBits, code.symbol));
        }

        /**
         * Decodes a string of Huffman encoded bytes.
         * @param bytes
         * @return
         */
        public String decode(byte[] bytes) {
            StringBuffer string = new StringBuffer(bytes.length);
            BitBuffer buffer = new BitBuffer(bytes);
            while (buffer.hasRemaining()) {
                TableEntry symbol = lookup(lookupTable, buffer);
                if (symbol != null) {
                    string.append(symbol.character);
                }
            }
            return string.toString();
        }

        /**
         * Performs (recursive) symbol lookup for the first character in the buffer with the given table.
         *
         * @param table  the lookup table used for the lookup (is an argument to allow for recursion)
         * @param buffer the buffer containing the bits that will be decoded.
         * @return the symbol represented by the code or null if there is no match
         */
        private TableEntry lookup(TableEntry[] table, BitBuffer buffer) {
            int key = (int) buffer.peek() & 0xff;
            TableEntry mappedSymbol = table[key];
            if (mappedSymbol.isSymbol()) {
                buffer.shift(mappedSymbol.codeLength);
                return mappedSymbol;
            }
            else if (buffer.remaining() >= KEY_SIZE) {
                if (mappedSymbol.subTable == null) {
                    throw new IllegalStateException("Missing subtable!");
                }
                buffer.shift(KEY_SIZE);
                return lookup(mappedSymbol.subTable, buffer);
            }
            else {
                // End of buffer contains some non-character bits (probably just 1's), as total length of character encodings
                // in the buffer is not a multiple of 8.
                buffer.shift(buffer.remaining());
                return null;
            }
        }

        /**
         * Adds a symbol with the given code to the lookup table recursively. If the code length is larger than 8, the
         * symbol will not be added to the table directly, but indirectly via one or more linked (nested) tables.
         *
         * @param table       the table to add the symbol to
         * @param code        the code to add as a String of 1's and 0's
         * @param symbolValue the symbol symbolValue to add (integer representation)
         */
        private void addToLookupTable(TableEntry[] table, String code, int symbolValue) {
            if (code.length() <= KEY_SIZE) {
                int codeValue = parseBits(code, code.length());
                TableEntry mappedSymbol = new TableEntry(symbolValue, code.length());
                generateCodeKeys(codeValue, code.length())
                        .forEach(key -> table[key] = mappedSymbol);
            }
            else {
                int prefixCode = parseBits(code, KEY_SIZE);
                String suffix = code.substring(KEY_SIZE);
                if (table[prefixCode] == null) {
                    table[prefixCode] = new TableEntry();
                }
                addToLookupTable(table[prefixCode].subTable, suffix, symbolValue);
            }
        }

        /**
         * Generates keys for the given code. As a code can be less than 8 bits, keys must be generated for all values for
         * the LSB's that are not part of the key. For example, if the code is 0b001100 (6 bits), keys are generated for all
         * values of the 2 least significant bits: 0b00110000, 0b00110001, 0b00110010, 0b00110011
         *
         * @param codeValue
         * @param bits
         * @return
         */
        private IntStream generateCodeKeys(int codeValue, int bits) {
            int baseValue = codeValue << (KEY_SIZE - bits);
            int maxAddition = (int) Math.pow(2, KEY_SIZE - bits);
            return IntStream.range(0, maxAddition).map(addition -> baseValue | addition);
        }

        private int parseBits(String code, int count) {
            return Integer.parseInt(code.substring(0, count), 2);
        }

        private static class TableEntry {

            final char character;
            final int codeLength;
            final TableEntry[] subTable;

            public TableEntry(int character, int codeLength) {
                this.character = (char) character;
                this.codeLength = codeLength;
                this.subTable = null;
            }

            public TableEntry() {
                this.character = 0;
                this.codeLength = 0;
                subTable = new TableEntry[(int) Math.pow(2, KEY_SIZE)];
                ;
            }

            boolean isSymbol() {
                return subTable == null;
            }
        }
    }

    /**
     * Encoder for Huffman code as specified by https://www.rfc-editor.org/rfc/rfc7541.html#appendix-B.
     * For each byte to encode, the huffman code for the symbol can be simply retrieved from the lookup table,
     * but assembling the result for all bytes involves a lot of bit shifting, as the code for an individual symbol
     * mostly has a (bit) length that is not a multiple of 8.
     */
    private static class Encoder {

        private final SymbolCodeEntry[] huffmanCode = new SymbolCodeEntry[257];

        public Encoder(List<SymbolCodeEntry> huffmanCode) {
            huffmanCode.stream().forEach(entry -> {
                this.huffmanCode[entry.symbol] = entry;
            });
        }

        public byte[] encode(byte[] string) {
            SymbolCodeEntry[] elements = new SymbolCodeEntry[string.length];
            // Lookup symbol for each byte
            for (int i = 0; i < string.length; i++) {
                elements[i] = huffmanCode[Byte.toUnsignedInt(string[i])];
            }
            int numberOfBits = Arrays.stream(elements).mapToInt(c -> c.length).sum();
            int encodingLength = ((numberOfBits - 1) / 8) + 1;

            // Append the symbol codes to buffer, shifting codes to fill up empty (bit) places.
            ByteBuffer buffer = ByteBuffer.allocate(encodingLength);
            ByteBuffer intBuffer = ByteBuffer.allocate(4);
            int emptyBits = 0;  // Number of empty bits (bits at the right not yet written) in the last byte written to buffer
            for (int i = 0; i < string.length; i++) {
                SymbolCodeEntry element = elements[i];
                if (emptyBits > 0) {
                    byte lastByte = buffer.get(buffer.position() - 1);
                    int mostSignificantBits;
                    if (element.length >= emptyBits) {
                        // Shift code to get the {emptyBits} most significant bits aligned at the right, e.g.
                        // lastByte = 10001... (3 empty bits); code 110101 shifted by 3 becomes 110 to fill in the empty bits.
                        // So, shift element.length bytes to the right and then emptyBits to the left; as emptyBits <= element.length...
                        int shiftAmount = element.length - emptyBits;
                        mostSignificantBits = element.asInt >> shiftAmount;
                    }
                    else {
                        // Shift code to fill all the emptyBits, e.g.
                        // lastByte = 01...... (6 empty bits); code 00101 shift by 1 becomes 001010 to fill in the empty bits (except the last)
                        // So, shift element.length bytes to the right and then emptyBits to the left; as emptyBits > element.length...
                        int shiftAmount = emptyBits - element.length;
                        mostSignificantBits = element.asInt << shiftAmount;
                    }
                    // Note that lastByte is a byte, so only the LSB of variable mostSignificantBits is used
                    lastByte |= mostSignificantBits;
                    buffer.put(buffer.position() - 1, lastByte);
                }
                if (element.length > emptyBits) {
                    // Shift 32 - element.length to the left to make bit pattern left aligned; and emptyBits more because that many bits is already encoded in last byte in buffer
                    int shift = 32 - (element.length) + emptyBits;
                    int bits = element.asInt << shift;
                    intBuffer.putInt(bits);
                    int byteCount = numberOfBytes(element.length - emptyBits);
                    for (int j = 0; j < byteCount; j++) {
                        buffer.put(intBuffer.get(j));
                    }
                    intBuffer.clear();
                    emptyBits = shift % 8;
                }
                else {
                    emptyBits -= element.length;
                }
            }
            if (emptyBits > 0) {
                // Fill empty bits with EOS, which is all ones; mask with all zeros and emptyBits ones.
                int mask = ~ (0xffffffff << emptyBits);
                buffer.put(encodingLength - 1, (byte) (buffer.get(encodingLength - 1) | mask));
            }
            return buffer.array();
        }

        /**
         * Returns the minimum number of bytes needed to store the given number of bits
         * @param numberOfBits
         * @return
         */
        private int numberOfBytes(int numberOfBits) {
            if (numberOfBits < 0) {
                throw new IllegalArgumentException("numberOfBits cannot be negative");
            }
            else {
                // n:       1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18
                // n/8:     0  0  0  0  0  0  0  1  1  1  1  1  1  1  1  2  2  2
                // (n-1)/8: 0  0  0  0  0  0  0  0  1  1  1  1  1  1  1  1  2  2   so: 1 + (n-1)/8 would work
                // (n+7)/8: 1  1  1  1  1  1  1  1  2  2  2  2  2  2  2  2  2  2   so: (n+7)/8 would work too
                return (numberOfBits + 7) / 8;
            }
        }
    }
}
