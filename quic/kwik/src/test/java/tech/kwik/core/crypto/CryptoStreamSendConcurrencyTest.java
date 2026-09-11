package tech.kwik.core.crypto;

import junit.framework.TestCase;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.impl.Role;
import tech.kwik.core.impl.Version;
import tech.kwik.core.impl.VersionHolder;
import tech.kwik.core.log.NullLogger;
import tech.kwik.core.send.Sender;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * Writing handshake data while the sender is draining it.
 * <p>
 * Two threads share {@code dataToSend}: whichever one the TLS engine runs on writes to it, and the
 * sender thread takes frames out of it. It is an {@code ArrayList} and upstream shares it between
 * them with no synchronization at all, which holds only while a flight is one message - then the
 * write has always finished before the sender is told there is anything to send.
 * <p>
 * The client's EncryptedExtensions of ALPS ends that. The flight becomes two messages, the first of
 * them flushes the sender, and the Finished is written while the sender thread is already inside the
 * list. What that produced, against the one host in the tests that negotiates ALPS, was four failed
 * connections in four hundred: {@code ArrayList.get(0)} handing back a null while an {@code add} grew
 * the array, or throwing "Index 0 out of bounds for length 0" while a {@code remove(0)} shifted it -
 * on the sender thread, which aborted the connection just after its handshake had succeeded.
 * <p>
 * So this is a race and not a case, and it is tested the way a race can be: both sides run for real,
 * many times over, and the assertion is that the bytes come out whole and in order. Against the
 * unsynchronized version it fails within a run or two.
 */
public class CryptoStreamSendConcurrencyTest extends TestCase {

    /** Enough messages that the two threads overlap; the failure needs one unlucky interleaving. */
    private static final int MESSAGES = 200;

    /** About the size of the handshake messages this really carries. */
    private static final int MESSAGE_SIZE = 64;

    public void testWritingWhileTheSenderDrainsKeepsTheStreamWhole() throws Exception {
        for (int attempt = 0; attempt < 20; attempt++) {
            runOnce();
        }
    }

    private void runOnce() throws Exception {
        AtomicReference<Function<Integer, QuicFrame>> frameSupplier = new AtomicReference<>();
        CryptoStream cryptoStream = new CryptoStream(new VersionHolder(Version.QUIC_version_1),
                EncryptionLevel.Handshake, Role.Client, null, new NullLogger(),
                new CapturingSender(frameSupplier));

        byte[] written = new byte[MESSAGES * MESSAGE_SIZE];
        for (int i = 0; i < written.length; i++) {
            written[i] = (byte) i;
        }

        CountDownLatch start = new CountDownLatch(1);
        AtomicReference<Throwable> senderFailure = new AtomicReference<>();
        List<CryptoFrame> frames = new ArrayList<>();

        Thread sender = new Thread(() -> {
            try {
                start.await();
                // As the sender loop does: ask for a frame whenever there is a request outstanding,
                // and keep asking until the writer is done and nothing is left.
                for (int i = 0; i < MESSAGES * 4; i++) {
                    Function<Integer, QuicFrame> supplier = frameSupplier.get();
                    if (supplier != null) {
                        QuicFrame frame = supplier.apply(1200);
                        if (frame != null) {
                            synchronized (frames) {
                                frames.add((CryptoFrame) frame);
                            }
                        }
                    }
                    Thread.yield();
                }
            }
            catch (Throwable failure) {
                senderFailure.set(failure);
            }
        });
        sender.start();

        start.countDown();
        for (int i = 0; i < MESSAGES; i++) {
            byte[] message = new byte[MESSAGE_SIZE];
            System.arraycopy(written, i * MESSAGE_SIZE, message, 0, MESSAGE_SIZE);
            cryptoStream.write(message);
        }
        sender.join();

        if (senderFailure.get() != null) {
            throw new AssertionError("the sender thread died while data was being written: "
                    + senderFailure.get(), senderFailure.get());
        }

        // Whatever it managed to take has to be the head of the stream, byte for byte and gap free.
        drainRest(frameSupplier, frames);
        assertEquals("the sender did not take everything that was written",
                written.length, totalLength(frames));
        byte[] sent = reassemble(frames, written.length);
        for (int i = 0; i < written.length; i++) {
            assertEquals("byte " + i + " of the crypto stream", written[i], sent[i]);
        }
    }

    /** The sender loop stops on its own count; anything still queued is taken here. */
    private static void drainRest(AtomicReference<Function<Integer, QuicFrame>> frameSupplier, List<CryptoFrame> frames) {
        Function<Integer, QuicFrame> supplier = frameSupplier.get();
        for (int i = 0; supplier != null && i < MESSAGES * 4; i++) {
            QuicFrame frame = supplier.apply(1200);
            if (frame == null) {
                return;
            }
            frames.add((CryptoFrame) frame);
        }
    }

    private static int totalLength(List<CryptoFrame> frames) {
        int total = 0;
        for (CryptoFrame frame : frames) {
            total += frame.getLength();
        }
        return total;
    }

    /**
     * The frames laid back down at their own offsets, which is what the peer does. An offset written
     * twice or a gap left behind shows up as a mismatch in the comparison above.
     */
    private static byte[] reassemble(List<CryptoFrame> frames, int length) {
        byte[] stream = new byte[length];
        for (CryptoFrame frame : frames) {
            byte[] data = frame.getStreamData();
            System.arraycopy(data, 0, stream, (int) frame.getOffset(), data.length);
        }
        return stream;
    }

    /** Keeps the last frame supplier the stream registered, which is what the real sender queues. */
    private static class CapturingSender implements Sender {

        private final AtomicReference<Function<Integer, QuicFrame>> frameSupplier;

        CapturingSender(AtomicReference<Function<Integer, QuicFrame>> frameSupplier) {
            this.frameSupplier = frameSupplier;
        }

        @Override
        public void send(Function<Integer, QuicFrame> frameSupplier, int minimumSize, EncryptionLevel level,
                         Consumer<QuicFrame> lostCallback) {
            this.frameSupplier.set(frameSupplier);
        }

        @Override
        public void send(QuicFrame frame, EncryptionLevel level) {
        }

        @Override
        public void send(QuicFrame frame, EncryptionLevel level, Consumer<QuicFrame> frameLostCallback) {
        }

        @Override
        public void sendAlternateAddress(QuicFrame frame, InetSocketAddress clientAddress) {
        }

        @Override
        public void setInitialToken(byte[] token) {
        }

        @Override
        public void sendAck(PnSpace pnSpace, int maxDelay) {
        }

        @Override
        public void sendProbe(EncryptionLevel level) {
        }

        @Override
        public void sendProbe(List<QuicFrame> frames, EncryptionLevel level) {
        }

        @Override
        public void packetProcessed(boolean expectingMore) {
        }

        @Override
        public void datagramProcessed(boolean expectingMore) {
        }

        @Override
        public void flush() {
        }

        @Override
        public int getPto() {
            return 0;
        }

        @Override
        public java.time.Instant lastAckElicitingSent() {
            return java.time.Instant.now();
        }
    }
}
