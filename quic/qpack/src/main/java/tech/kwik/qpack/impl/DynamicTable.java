/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator) and is distributed
 * with the vendored copy of Qpack; see quic/qpack/UPSTREAM.md.
 *
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the
 * implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser
 * General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.qpack.impl;

import java.util.ArrayList;
import java.util.List;

/**
 * The QPACK dynamic table of RFC 9204 section 3.2, as seen by a decoder.
 * <p>
 * Entries are appended by the peer's encoder stream and referred to by <em>absolute</em> index,
 * counted from the first entry ever inserted and never reused: an index is resolved against
 * {@link #insertCount()} and {@link #droppedCount()}, not against the current contents. That is what
 * makes a reference unambiguous while entries are being evicted at the other end of the table.
 * <p>
 * Two threads meet here. The encoder stream is read on its own thread and is the only writer; the
 * request threads read while decoding a field section, and block in
 * {@link #awaitInsertCount(long, long)} when a section refers to an entry that has not arrived yet -
 * which is what {@code SETTINGS_QPACK_BLOCKED_STREAMS} permits the encoder to do. So every method
 * here is synchronized on this object, and an encoder stream that dies wakes the waiters rather than
 * leaving them to time out.
 */
public class DynamicTable {

    /**
     * RFC 9204 section 3.2.1: "The size of an entry is the sum of its name's length in bytes, its
     * value's length in bytes, and 32 additional bytes."
     */
    private static final int ENTRY_OVERHEAD = 32;

    private final List<TableEntry> entries = new ArrayList<>();
    private final long maxCapacity;

    private long capacity;
    private long size;
    private long insertCount;
    private long droppedCount;
    private Throwable encoderStreamFailure;

    /**
     * @param maxCapacity the value this end advertised as {@code SETTINGS_QPACK_MAX_TABLE_CAPACITY};
     *                    the peer may set any capacity up to it, and none until it does.
     */
    public DynamicTable(long maxCapacity) {
        this.maxCapacity = maxCapacity;
    }

    public long maxCapacity() {
        return maxCapacity;
    }

    /**
     * RFC 9204 section 4.5.1.1: {@code MaxEntries = floor(MaxTableCapacity / 32)}. It is derived from
     * the advertised maximum rather than the current capacity, because it is the modulus the Required
     * Insert Count is encoded against and both ends have to agree on it before any capacity is set.
     */
    public long maxEntries() {
        return maxCapacity / ENTRY_OVERHEAD;
    }

    public synchronized long insertCount() {
        return insertCount;
    }

    public synchronized long droppedCount() {
        return droppedCount;
    }

    public synchronized long capacity() {
        return capacity;
    }

    /**
     * RFC 9204 section 3.2.3, the Set Dynamic Table Capacity instruction. "The encoder MUST NOT set a
     * dynamic table capacity that exceeds the maximum dynamic table capacity", which is the value
     * this end advertised.
     */
    public synchronized void setCapacity(long newCapacity) {
        if (newCapacity > maxCapacity) {
            throw new QPackEncoderStreamException("Set Dynamic Table Capacity " + newCapacity
                    + " exceeds the advertised SETTINGS_QPACK_MAX_TABLE_CAPACITY " + maxCapacity);
        }
        capacity = newCapacity;
        evictTo(capacity);
    }

    /**
     * Appends an entry, evicting from the oldest end until it fits. RFC 9204 section 3.2.2: "the
     * encoder MUST NOT insert an entry that has a size larger than the dynamic table capacity", so an
     * entry that still does not fit an emptied table is the encoder's error and not a reason to drop
     * it quietly - the two tables would be out of step from then on.
     */
    public synchronized void insert(String name, String value) {
        long entrySize = entrySize(name, value);
        evictTo(capacity - entrySize);
        if (size + entrySize > capacity) {
            throw new QPackEncoderStreamException("entry of " + entrySize + " bytes does not fit a"
                    + " dynamic table of capacity " + capacity + " (" + size + " bytes in use): " + name);
        }
        entries.add(new TableEntry(name, value));
        size += entrySize;
        insertCount++;
        notifyAll();
    }

    /**
     * The entry at an absolute index, which must still be present: an index below
     * {@link #droppedCount()} names an entry the encoder should have known was evictable, and one at
     * or above {@link #insertCount()} names an entry that was never inserted.
     *
     * @param context what referred to the entry, for the message when it is not there
     */
    public synchronized TableEntry get(long absoluteIndex, String context) {
        if (absoluteIndex < droppedCount || absoluteIndex >= insertCount) {
            throw new HttpQPackDecompressionFailedException(context + " refers to absolute index "
                    + absoluteIndex + ", outside the dynamic table's [" + droppedCount + ", "
                    + insertCount + ") - capacity " + capacity + ", " + size + " bytes in use");
        }
        return entries.get((int) (absoluteIndex - droppedCount));
    }

    /**
     * Blocks until at least {@code required} entries have been inserted, which is what a field
     * section whose Required Insert Count runs ahead of the encoder stream is waiting for.
     *
     * @param timeoutMillis how long to wait before giving up; a section that never becomes decodable
     *                      would otherwise hang the request forever
     */
    public synchronized void awaitInsertCount(long required, long timeoutMillis) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        while (insertCount < required) {
            if (encoderStreamFailure != null) {
                throw new HttpQPackDecompressionFailedException("the encoder stream failed while a field"
                        + " section was blocked on Required Insert Count " + required + " (at " + insertCount + ")",
                        encoderStreamFailure);
            }
            long remaining = deadline - System.currentTimeMillis();
            if (remaining <= 0) {
                throw new HttpQPackDecompressionFailedException("timed out waiting for Required Insert Count "
                        + required + "; the encoder stream delivered " + insertCount + " entries in "
                        + timeoutMillis + " ms");
            }
            wait(remaining);
        }
    }

    /**
     * Reports that the encoder stream will deliver nothing more, so that anything blocked on an
     * insert that is never coming fails with the reason rather than with a timeout.
     */
    public synchronized void encoderStreamFailed(Throwable cause) {
        encoderStreamFailure = cause;
        notifyAll();
    }

    private void evictTo(long targetSize) {
        while (size > targetSize && !entries.isEmpty()) {
            TableEntry evicted = entries.remove(0);
            size -= entrySize(evicted.getKey(), evicted.getValue());
            droppedCount++;
        }
    }

    /**
     * The name and the value are held as one char per byte - they were read either as ISO-8859-1 or
     * out of the Huffman decoder, which emits one char per decoded octet - so the length in chars is
     * the length in bytes RFC 9204 section 3.2.1 asks for.
     */
    private static long entrySize(String name, String value) {
        return name.length() + value.length() + ENTRY_OVERHEAD;
    }
}
