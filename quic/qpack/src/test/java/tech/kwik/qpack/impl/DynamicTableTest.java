package tech.kwik.qpack.impl;

import junit.framework.TestCase;

/**
 * The dynamic table's own rules, which are this project's code rather than qpack's.
 * <p>
 * {@link Rfc9204ExamplesTest} settles that the table agrees with the RFC's worked exchange; this
 * settles what it does at the edges that exchange never reaches - an index that has been evicted, a
 * capacity the encoder is not entitled to, an entry that cannot fit, and a field section left waiting
 * for an insert that never comes. Every one of those is a case where the two ends' tables would
 * silently drift apart if it were answered with a null or a shrug, and every later field section on
 * the connection would decode to something other than what was sent.
 */
public class DynamicTableTest extends TestCase {

    /** Two of these fit in 220 bytes and three do not, which is the appendix's arithmetic. */
    private static final String NAME = ":authority";          // 10
    private static final String VALUE = "www.example.com";    // 15, so the entry is 57

    public void testAnEntryCostsItsNameItsValueAndThirtyTwoBytes() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);

        table.insert(NAME, VALUE);

        assertEquals("RFC 9204 section 3.2.1: name + value + 32", 57, table.size());
    }

    /** MaxEntries is the modulus a Required Insert Count is encoded against; section 4.5.1.1. */
    public void testMaxEntriesComesFromTheAdvertisedMaximumAndNotTheCurrentCapacity() {
        DynamicTable table = new DynamicTable(220);
        table.setCapacity(64);

        assertEquals(220 / 32, table.maxEntries());
    }

    /**
     * An index is absolute: it counts from the first entry ever inserted, so it goes on naming the
     * same entry while the table is evicted underneath it, and stops resolving when that entry goes.
     * <p>
     * This is the bug the vendored table was written to fix - upstream indexed relative to the newest
     * entry, so a reference resolved to a different header after every insert - and it is invisible
     * without an assertion like this one, because both readings return a header.
     */
    public void testAnIndexNamesTheSameEntryWhileTheTableMovesUnderIt() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(220);

        table.insert("first", "1");
        table.insert("second", "2");
        assertEquals("first", table.get(0, "test").getKey());
        assertEquals("second", table.get(1, "test").getKey());

        table.insert("third", "3");
        assertEquals("the entry at absolute index 1 is still the second one inserted",
                "second", table.get(1, "test").getKey());
        assertEquals("third", table.get(2, "test").getKey());
    }

    /** Evicted from the oldest end, and an index that named an evicted entry is an error. */
    public void testAnEvictedIndexIsRefusedRatherThanResolvedToWhateverIsThereNow() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(120);   // room for two 57 byte entries and not three

        table.insert(NAME, VALUE);
        table.insert(NAME, VALUE);
        assertEquals(0, table.droppedCount());

        table.insert(NAME, VALUE);
        assertEquals(1, table.droppedCount());
        assertEquals(3, table.insertCount());

        try {
            table.get(0, "Indexed Field Line");
            fail("absolute index 0 has been evicted and must not resolve");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertTrue("the message must say what was asked for and what is there: "
                    + expected.getMessage(),
                    expected.getMessage().contains("Indexed Field Line")
                            && expected.getMessage().contains("absolute index 0")
                            && expected.getMessage().contains("[1, 3)"));
        }
    }

    /** And so is one that was never inserted, which is the other end of the same range. */
    public void testAnIndexThatWasNeverInsertedIsRefused() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);
        table.insert(NAME, VALUE);

        try {
            table.get(1, "Duplicate");
            fail("absolute index 1 has not been inserted yet");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("[0, 1)"));
        }
    }

    /**
     * RFC 9204 section 3.2.3: "The encoder MUST NOT set a dynamic table capacity that exceeds the
     * maximum dynamic table capacity." An encoder that does is not one to keep decoding for - it is
     * working from a different idea of the table than this end has.
     */
    public void testACapacityAboveTheAdvertisedMaximumIsRefused() {
        DynamicTable table = new DynamicTable(220);

        try {
            table.setCapacity(221);
            fail("a capacity above the advertised maximum must be refused");
        }
        catch (QPackEncoderStreamException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("221")
                    && expected.getMessage().contains("220"));
        }
    }

    /** Lowering the capacity evicts down to it, which is what section 3.2.3 says it does. */
    public void testLoweringTheCapacityEvicts() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);
        table.insert(NAME, VALUE);
        table.insert(NAME, VALUE);

        table.setCapacity(60);

        assertEquals("only the newest entry still fits", 1, table.droppedCount());
        assertEquals(57, table.size());
        assertEquals(NAME, table.get(1, "test").getKey());
    }

    /**
     * RFC 9204 section 3.2.2: "the encoder MUST NOT insert an entry that has a size larger than the
     * dynamic table capacity". Dropping it quietly would leave the two tables one entry out of step
     * for the rest of the connection, and every index after it pointing at the wrong header.
     */
    public void testAnEntryTooLargeForTheTableIsAnError() {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(40);

        try {
            table.insert(NAME, VALUE);
            fail("a 57 byte entry does not fit a table of 40 and must not be dropped quietly");
        }
        catch (QPackEncoderStreamException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("57")
                    && expected.getMessage().contains("40"));
        }
        assertEquals("and nothing was inserted", 0, table.insertCount());
    }

    /** A capacity of zero is a table nothing can be put in, which is what the default is. */
    public void testNoCapacityMeansNoInserts() {
        DynamicTable table = new DynamicTable(0);

        try {
            table.insert("a", "b");
            fail("a table with no capacity cannot hold an entry");
        }
        catch (QPackEncoderStreamException expected) {
            assertEquals(0, table.insertCount());
        }
    }

    /**
     * A blocked field section waits for the insert it needs and goes on as soon as it arrives, which
     * is what {@code SETTINGS_QPACK_BLOCKED_STREAMS} lets the encoder count on.
     */
    public void testASectionBlockedOnAnInsertWakesWhenItArrives() throws Exception {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);

        Thread encoderStream = new Thread(() -> {
            try {
                Thread.sleep(50);
                table.insert(NAME, VALUE);
            }
            catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
        });
        encoderStream.start();

        table.awaitInsertCount(1, 5000);

        assertEquals(1, table.insertCount());
        encoderStream.join();
    }

    /**
     * An insert that never arrives ends the request instead of hanging it. There is no such timeout in
     * RFC 9204 - the encoder is trusted to send what it made a section depend on - but a peer that
     * does not is otherwise indistinguishable from one that is slow.
     */
    public void testASectionBlockedOnAnInsertThatNeverComesGivesUp() throws Exception {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);

        try {
            table.awaitInsertCount(1, 50);
            fail("waiting for an insert that never comes must end");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("timed out"));
        }
    }

    /**
     * And when the encoder stream is known to be gone, the waiter is told that rather than being left
     * to time out - the reason is worth more than the delay, and it is the reason.
     */
    public void testAFailedEncoderStreamWakesTheWaiterWithItsCause() throws Exception {
        DynamicTable table = new DynamicTable(4096);
        table.setCapacity(4096);
        Exception cause = new IllegalStateException("the connection went away");

        new Thread(() -> table.encoderStreamFailed(cause)).start();

        try {
            table.awaitInsertCount(1, 5000);
            fail("a waiter must not sit out the timeout when the stream it waits on has failed");
        }
        catch (HttpQPackDecompressionFailedException expected) {
            assertSame(cause, expected.getCause());
        }
    }
}
