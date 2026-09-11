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
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to implement the QPACK
 * dynamic table of RFC 9204; see quic/qpack/UPSTREAM.md.
 */
package tech.kwik.qpack.impl;

import tech.kwik.qpack.Decoder;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static tech.kwik.qpack.impl.PrefixedInteger.parsePrefixedInteger;
import static tech.kwik.qpack.impl.PrefixedInteger.writePrefixedInteger;


public class DecoderImpl implements Decoder {

    /**
     * How long a field section may stay blocked on entries the encoder stream has not delivered.
     * There is no such limit in RFC 9204 - the encoder is trusted to send the inserts it made a
     * section depend on - but without one an encoder that never does hangs the request forever.
     */
    private static final long BLOCKED_SECTION_TIMEOUT_MILLIS = 10_000;

    private final Huffman huffman;
    private final StaticTable staticTable;

    /**
     * The stream the field section being decoded on this thread arrived on, needed for the Section
     * Acknowledgment that RFC 9204 section 4.4.1 requires once it has been decoded. The QPACK
     * {@link Decoder} interface is handed the section's bytes and nothing else, so the id has to come
     * from the caller, and it is per thread because a connection decodes several sections at once.
     */
    private final ThreadLocal<Long> sectionStreamId = new ThreadLocal<>();

    private final AtomicInteger blockedStreams = new AtomicInteger();

    private final AtomicLong dynamicTableReferences = new AtomicLong();

    private DynamicTable dynamicTable = new DynamicTable(0);
    private int maxBlockedStreams;
    private OutputStream decoderStream;
    private long pendingInsertCountIncrement;

    public DecoderImpl() {
        staticTable = StaticTable.getInstance();
        huffman = Huffman.getInstance();
    }

    /**
     * The dynamic table capacity this end advertises as {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY}.
     * Zero, the default, is what says there is no dynamic table at all: the peer may then insert
     * nothing and every field section is decodable on its own.
     * <p>
     * Must be set before the connection carries any traffic, because it is the modulus the peer
     * encodes a Required Insert Count against.
     */
    public void setMaxTableCapacity(long maxTableCapacity) {
        dynamicTable = new DynamicTable(maxTableCapacity);
    }

    /**
     * The number of streams this end advertises as {@code SETTINGS_QPACK_BLOCKED_STREAMS}, which is
     * how many field sections the encoder may send that refer to entries it has not yet delivered.
     */
    public void setMaxBlockedStreams(int maxBlockedStreams) {
        this.maxBlockedStreams = maxBlockedStreams;
    }

    public int getMaxBlockedStreams() {
        return maxBlockedStreams;
    }

    /**
     * The QPACK decoder stream (RFC 9204 section 4.4), on which the peer's encoder is told what has
     * arrived and what has been decoded. Without it the peer's Known Received Count never moves and
     * it can only refer to a dynamic table entry by risking a blocked stream.
     */
    public void setDecoderStream(OutputStream decoderStream) {
        this.decoderStream = decoderStream;
    }

    /**
     * Names the stream the next field section decoded on this thread came in on. Set by the HTTP/3
     * connection, which is the only place that knows both.
     *
     * @param streamId null when the caller cannot tell, which leaves a section that needs
     *                 acknowledging to fail rather than be acknowledged against whatever this thread
     *                 decoded last
     */
    public void setSectionStreamId(Long streamId) {
        sectionStreamId.set(streamId);
    }

    public DynamicTable getDynamicTable() {
        return dynamicTable;
    }

    /**
     * How many field line representations have been resolved against the dynamic table. Inserting
     * entries and referring to them are separate capabilities and a peer can use the first without
     * the second, so this counts the second: it is the only way to tell that a connection really
     * exercised the dynamic table rather than merely filling one.
     */
    public long getDynamicTableReferences() {
        return dynamicTableReferences.get();
    }

    private TableEntry referenced(long absoluteIndex, String representation) {
        dynamicTableReferences.incrementAndGet();
        return dynamicTable.get(absoluteIndex, representation);
    }

    /**
     * Reads the peer's encoder stream (RFC 9204 section 4.3) until it ends, which it should not do
     * before the connection does. Runs on its own thread: it is the only writer of the dynamic table,
     * and the request threads read it.
     */
    public void decodeEncoderStream(InputStream inputStream) throws IOException {
        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream, 16);
        int instruction = peek(pushbackInputStream);

        while (instruction >= 0) {  // EOF returns -1
            // RFC 9204 section 4.3 defines four instructions and they exhaust the first byte, so
            // there is no "unknown instruction" left to reject here.
            if ((instruction & 0x80) == 0x80) {
                parseInsertWithNameReference(pushbackInputStream);
            }
            else if ((instruction & 0xc0) == 0x40) {
                parseInsertWithoutNameReference(pushbackInputStream);
            }
            else if ((instruction & 0xe0) == 0x20) {
                parseSetDynamicTableCapacity(pushbackInputStream);
            }
            else {
                parseDuplicate(pushbackInputStream);
            }

            // Tell the encoder what has arrived, once per batch rather than once per insert: until it
            // hears, it can only refer to these entries by blocking a stream.
            if (pushbackInputStream.available() == 0) {
                flushInsertCountIncrement();
            }
            instruction = peek(pushbackInputStream);
        }
        flushInsertCountIncrement();
    }

    @Override
    public List<Map.Entry<String, String>> decodeStream(InputStream inputStream) throws IOException {
        PushbackInputStream pushbackInputStream = new PushbackInputStream(inputStream, 16);
        List<Map.Entry<String, String>> headers = new ArrayList<>();

        // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.1
        // "Header Block Prefix"
        long requiredInsertCount = decodeRequiredInsertCount(parsePrefixedInteger(8, pushbackInputStream));
        byte deltaBaseFirstByte = read(pushbackInputStream);
        pushbackInputStream.unread(deltaBaseFirstByte);
        boolean baseIsBelowRequiredInsertCount = (deltaBaseFirstByte & 0x80) == 0x80;
        long deltaBase = parsePrefixedInteger(7, pushbackInputStream);
        // "Base = ReqInsertCount + DeltaBase" when the sign bit is 0, "Base = ReqInsertCount - DeltaBase - 1" when it is 1.
        long base = baseIsBelowRequiredInsertCount
                ? requiredInsertCount - deltaBase - 1
                : requiredInsertCount + deltaBase;

        awaitRequiredInsertCount(requiredInsertCount);

        int instruction = peek(pushbackInputStream);
        while (instruction >= 0) {  // EOF returns -1
            Map.Entry<String, String> entry;
            if ((instruction & 0x80) == 0x80) {
                entry = parseIndexedHeaderField(pushbackInputStream, base);
            }
            else if ((instruction & 0xc0) == 0x40) {
                entry = parseLiteralHeaderFieldWithNameReference(pushbackInputStream, base);
            }
            else if ((instruction & 0xe0) == 0x20) {
                entry = parseLiteralHeaderFieldWithoutNameReference(pushbackInputStream);
            }
            else if ((instruction & 0xf0) == 0x10) {
                entry = parseIndexedHeaderFieldWithPostBaseIndex(pushbackInputStream, base);
            }
            else {
                // RFC 9204 section 4.5 defines six representations and they exhaust the first byte;
                // 0000xxxx is the last of them.
                entry = parseLiteralHeaderFieldWithPostBaseNameReference(pushbackInputStream, base);
            }

            headers.add(entry);
            instruction = peek(pushbackInputStream);
        }

        acknowledgeSection(requiredInsertCount);
        return headers;
    }

    /**
     * RFC 9204 section 4.5.1.1. The Required Insert Count is sent modulo twice the number of entries
     * the table can hold, so that it stays small; recovering it needs the number of inserts this end
     * has seen, and a value that cannot be reconciled with that is an error rather than a guess.
     */
    long decodeRequiredInsertCount(long encodedInsertCount) {
        if (encodedInsertCount == 0) {
            return 0;
        }
        long maxEntries = dynamicTable.maxEntries();
        if (maxEntries == 0) {
            throw new HttpQPackDecompressionFailedException("field section requires " + encodedInsertCount
                    + " dynamic table entries, but this end advertised no dynamic table capacity");
        }
        long fullRange = 2 * maxEntries;
        if (encodedInsertCount > fullRange) {
            throw new HttpQPackDecompressionFailedException("encoded Required Insert Count "
                    + encodedInsertCount + " exceeds the full range " + fullRange);
        }
        long maxValue = dynamicTable.insertCount() + maxEntries;
        long maxWrapped = (maxValue / fullRange) * fullRange;
        long requiredInsertCount = maxWrapped + encodedInsertCount - 1;
        if (requiredInsertCount > maxValue) {
            if (requiredInsertCount <= fullRange) {
                throw new HttpQPackDecompressionFailedException("encoded Required Insert Count "
                        + encodedInsertCount + " does not resolve: " + requiredInsertCount
                        + " is above the maximum " + maxValue + " and cannot be unwrapped");
            }
            requiredInsertCount -= fullRange;
        }
        if (requiredInsertCount == 0) {
            throw new HttpQPackDecompressionFailedException("encoded Required Insert Count "
                    + encodedInsertCount + " resolves to zero, which is only encoded as zero");
        }
        return requiredInsertCount;
    }

    /**
     * Waits for the entries a field section refers to, which is what {@code
     * SETTINGS_QPACK_BLOCKED_STREAMS} allows the encoder to make this end do. More streams blocked at
     * once than were advertised is the encoder exceeding what it was given.
     */
    private void awaitRequiredInsertCount(long requiredInsertCount) throws IOException {
        if (requiredInsertCount <= dynamicTable.insertCount()) {
            return;
        }
        int blocked = blockedStreams.incrementAndGet();
        try {
            if (blocked > maxBlockedStreams) {
                throw new HttpQPackDecompressionFailedException("field section requires insert count "
                        + requiredInsertCount + " with " + dynamicTable.insertCount() + " delivered, which would"
                        + " block " + blocked + " streams; this end advertised SETTINGS_QPACK_BLOCKED_STREAMS "
                        + maxBlockedStreams);
            }
            dynamicTable.awaitInsertCount(requiredInsertCount, BLOCKED_SECTION_TIMEOUT_MILLIS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while blocked on Required Insert Count " + requiredInsertCount, e);
        }
        finally {
            blockedStreams.decrementAndGet();
        }
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.2
    void parseInsertWithNameReference(PushbackInputStream inputStream) throws IOException {
        byte first = read(inputStream);
        inputStream.unread(first);
        boolean referStatic = (first & 0x40) == 0x40;

        long index = parsePrefixedInteger(6, inputStream);
        String name = referStatic
                ? staticTable.lookupName((int) index)
                : dynamicTable.get(relativeToInsertPoint(index), "Insert With Name Reference").getKey();

        String value = parseStringValue(inputStream);
        insert(name, value);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.3
    void parseInsertWithoutNameReference(PushbackInputStream inputStream) throws IOException {
        String name = parseStringValue(5, inputStream);
        String value = parseStringValue(inputStream);
        insert(name, value);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.1
    void parseSetDynamicTableCapacity(PushbackInputStream inputStream) throws IOException {
        dynamicTable.setCapacity(parsePrefixedInteger(5, inputStream));
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.3.4
    void parseDuplicate(PushbackInputStream inputStream) throws IOException {
        long index = parsePrefixedInteger(5, inputStream);
        TableEntry entry = dynamicTable.get(relativeToInsertPoint(index), "Duplicate");
        insert(entry.getKey(), entry.getValue());
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.2
    Map.Entry<String, String> parseIndexedHeaderField(PushbackInputStream inputStream, long base) throws IOException {
        byte first = read(inputStream);
        inputStream.unread(first);
        boolean inStaticTable = (first & 0x40) == 0x40;
        long index = parsePrefixedInteger(6, inputStream);

        return inStaticTable
                ? staticTable.lookupNameValue((int) index)
                : referenced(relativeToBase(base, index), "Indexed Field Line");
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.3
    Map.Entry<String, String> parseIndexedHeaderFieldWithPostBaseIndex(PushbackInputStream inputStream, long base) throws IOException {
        long index = parsePrefixedInteger(4, inputStream);
        return referenced(base + index, "Indexed Field Line With Post-Base Index");
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.4
    Map.Entry<String, String> parseLiteralHeaderFieldWithNameReference(PushbackInputStream inputStream, long base) throws IOException {
        byte first = read(inputStream);
        inputStream.unread(first);
        boolean inStaticTable = (first & 0x10) == 0x10;
        long nameIndex = parsePrefixedInteger(4, inputStream);
        String name = inStaticTable
                ? staticTable.lookupName((int) nameIndex)
                : referenced(relativeToBase(base, nameIndex), "Literal Field Line With Name Reference").getKey();

        String value = parseStringValue(inputStream);
        return new AbstractMap.SimpleEntry<>(name, value);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.5
    Map.Entry<String, String> parseLiteralHeaderFieldWithPostBaseNameReference(PushbackInputStream inputStream, long base) throws IOException {
        long nameIndex = parsePrefixedInteger(3, inputStream);
        String name = referenced(base + nameIndex, "Literal Field Line With Post-Base Name Reference").getKey();

        String value = parseStringValue(inputStream);
        return new AbstractMap.SimpleEntry<>(name, value);
    }

    // https://www.rfc-editor.org/rfc/rfc9204.html#section-4.5.6
    Map.Entry<String, String> parseLiteralHeaderFieldWithoutNameReference(PushbackInputStream inputStream) throws IOException {
        String name = parseStringValue(3, inputStream);
        String value = parseStringValue(inputStream);
        return new AbstractMap.SimpleEntry<>(name, value);
    }

    /**
     * RFC 9204 section 3.2.5: on the encoder stream a relative index counts back from the entry that
     * is about to be added, so entry 0 is the one inserted last.
     */
    private long relativeToInsertPoint(long relativeIndex) {
        return dynamicTable.insertCount() - relativeIndex - 1;
    }

    /**
     * RFC 9204 section 3.2.6: in a field section a relative index counts back from the Base, so that
     * the section keeps meaning the same entries however many inserts happen after it was encoded.
     */
    private long relativeToBase(long base, long relativeIndex) {
        return base - relativeIndex - 1;
    }

    private void insert(String name, String value) {
        dynamicTable.insert(name, value);
        pendingInsertCountIncrement++;
    }

    /**
     * RFC 9204 section 4.4.3, Insert Count Increment: how many entries have arrived since this end
     * last said. Until the encoder hears this, its Known Received Count stays where it was and it
     * cannot refer to the new entries without blocking a stream.
     */
    private void flushInsertCountIncrement() throws IOException {
        OutputStream stream = decoderStream;
        if (pendingInsertCountIncrement == 0 || stream == null) {
            return;
        }
        synchronized (stream) {
            writePrefixedInteger(6, (byte) 0x00, pendingInsertCountIncrement, stream);
            stream.flush();
        }
        pendingInsertCountIncrement = 0;
    }

    /**
     * RFC 9204 section 4.4.1: "After the decoder finishes decoding a field section encoded using
     * representations containing dynamic table references, it MUST emit a Section Acknowledgment
     * instruction." A section with a Required Insert Count of zero contains none, and is not
     * acknowledged.
     */
    private void acknowledgeSection(long requiredInsertCount) throws IOException {
        if (requiredInsertCount == 0) {
            return;
        }
        OutputStream stream = decoderStream;
        Long streamId = sectionStreamId.get();
        if (stream == null || streamId == null) {
            throw new HttpQPackDecompressionFailedException("a field section with Required Insert Count "
                    + requiredInsertCount + " must be acknowledged, but "
                    + (stream == null ? "no decoder stream was opened" : "the stream it arrived on is not known"));
        }
        synchronized (stream) {
            writePrefixedInteger(7, (byte) 0x80, streamId, stream);
            stream.flush();
        }
    }

    /**
     * The longest string literal this will allocate a buffer for. A field line's name or value is a
     * header, so this is far above anything real; it is here because the length prefix is a 62 bit
     * integer and casting one to int to size an array turns "impossibly long" into a negative array
     * size or a silent truncation. RFC 9204 sets no limit on the encoding, so this is a limit on what
     * this end will believe before it has seen the bytes, not a claim about the protocol.
     */
    private static final long MAX_STRING_LENGTH = 1 << 20;

    /**
     * The declared length as an int, or an error. Never a truncated one: {@code (int)} on a 62 bit
     * value can come out negative, and {@code new byte[negative]} is a NegativeArraySizeException
     * from somewhere that says nothing about the connection it came from.
     */
    private static int stringLength(long declaredLength) {
        if (declaredLength > MAX_STRING_LENGTH) {
            throw new HttpQPackDecompressionFailedException("a string literal declares " + declaredLength
                    + " bytes, past the " + MAX_STRING_LENGTH + " bytes this decoder will allocate for");
        }
        return (int) declaredLength;
    }

    private String parseStringValue(PushbackInputStream inputStream) throws IOException {
        byte firstByte = read(inputStream);
        inputStream.unread(firstByte);
        boolean huffmanEncoded = (firstByte & 0x80) == 0x80;
        int valueLength = stringLength(parsePrefixedInteger(7, inputStream));
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
        int length = stringLength(parsePrefixedInteger(prefixLength, inputStream));
        byte[] rawBytes = new byte[length];
        readExact(inputStream, rawBytes);
        return huffmanEncoded? huffman.decode(rawBytes): new String(rawBytes, StandardCharsets.ISO_8859_1);
    }

    private static int peek(PushbackInputStream inputStream) throws IOException {
        int value = inputStream.read();
        if (value >= 0) {
            inputStream.unread(value);
        }
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

    private void readExact(InputStream stream, byte[] data) throws IOException {
        int read = stream.readNBytes(data, 0, data.length);
        if (read != data.length) {
            throw new EOFException();
        }
    }
}
