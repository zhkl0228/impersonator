package tech.kwik.core.impl;

import junit.framework.TestCase;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.send.Sender;

import java.net.InetSocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The two ways a connection is kept alive: a PING at an interval for as long as it lives, and kwik's own total time.
 */
public class KeepAliveActorTest extends TestCase {

    public void testPingsAtTheIntervalUntilShutDown() throws Exception {
        PingCounter sender = new PingCounter();
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
        KeepAliveActor actor = KeepAliveActor.every(VersionHolder.withDefault(), Duration.ofMillis(100), sender,
                () -> true, scheduler);
        TimeUnit.MILLISECONDS.sleep(550);
        int sent = sender.pings.get();
        assertTrue("five intervals, got " + sent + " PINGs", sent >= 4 && sent <= 6);

        actor.shutdown();
        assertTrue(scheduler.awaitTermination(1, TimeUnit.SECONDS));
        int atShutdown = sender.pings.get();
        TimeUnit.MILLISECONDS.sleep(300);
        assertEquals("nothing after shutdown", atShutdown, sender.pings.get());
    }

    /** A connection that ended some other way than through shutdown stops the PINGs, and the thread, by itself. */
    public void testStopsOnceTheConnectionIsGone() throws Exception {
        PingCounter sender = new PingCounter();
        AtomicBoolean alive = new AtomicBoolean(true);
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
        KeepAliveActor.every(VersionHolder.withDefault(), Duration.ofMillis(100), sender, alive::get, scheduler);
        TimeUnit.MILLISECONDS.sleep(250);
        assertTrue(sender.pings.get() >= 1);

        alive.set(false);
        assertTrue("the thread must end once the connection is gone", scheduler.awaitTermination(1, TimeUnit.SECONDS));
        int atEnd = sender.pings.get();
        TimeUnit.MILLISECONDS.sleep(300);
        assertEquals(atEnd, sender.pings.get());
    }

    /**
     * kwik's own keep-alive takes a total time, not an interval: 10 seconds against a 30-second idle timeout pings at
     * 15 seconds, and 10 is less than one such interval, so nothing is ever scheduled. That is what hysteria2's
     * "keep alive every 10 seconds" amounted to.
     */
    public void testKwiksOwnKeepAliveOfLessThanAnIntervalSendsNothing() {
        PingCounter sender = new PingCounter();
        ScheduledThreadPoolExecutor scheduler = new ScheduledThreadPoolExecutor(1);
        try {
            new KeepAliveActor(Clock.systemUTC(), VersionHolder.withDefault(), 10, 30_000, sender, scheduler);
            assertTrue("no PING scheduled at all", scheduler.getQueue().isEmpty());

            new KeepAliveActor(Clock.systemUTC(), VersionHolder.withDefault(), 3600, 30_000, sender, scheduler);
            assertEquals("an hour in total does schedule one, 15 seconds out", 1, scheduler.getQueue().size());
        } finally {
            scheduler.shutdownNow();
        }
    }

    /** Counts the PINGs; nothing else of a sender is used by the keep-alive. */
    private static final class PingCounter implements Sender {
        final AtomicInteger pings = new AtomicInteger();

        @Override
        public void send(QuicFrame frame, EncryptionLevel level) {
            assertTrue("only PINGs, got " + frame, frame instanceof PingFrame);
            assertEquals(EncryptionLevel.App, level);
            pings.incrementAndGet();
        }

        @Override
        public void flush() {
        }

        @Override
        public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level,
                         Consumer<QuicFrame> lostCallback) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void sendAlternateAddress(QuicFrame frame, InetSocketAddress clientAddress) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setInitialToken(byte[] token) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void sendAck(PnSpace pnSpace, int maxDelay) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void sendProbe(EncryptionLevel level) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void packetProcessed(boolean expectingMore) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void datagramProcessed(boolean expectingMore) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Instant lastAckElicitingSent() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int getPto() {
            throw new UnsupportedOperationException();
        }
    }
}
