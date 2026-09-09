/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator), which adds browser
 * fingerprint control to Kwik, an implementation of QUIC in Java.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.core.send;

import tech.kwik.core.frame.CryptoFrame;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.frame.PingFrame;
import tech.kwik.core.frame.QuicFrame;
import tech.kwik.core.generic.VariableLengthInteger;
import tech.kwik.core.impl.Version;
import tech.kwik.core.packet.QuicPacket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * Scrambles an Initial packet the way Chrome does, so that its first flight does not look like one
 * message in one frame.
 * <p>
 * Chrome sends its ClientHello as a handful of CRYPTO frames carrying the pieces <em>out of order</em>,
 * with PING frames and runs of PADDING scattered between them. A capture of Chrome 152 shows one
 * Initial holding, in this order: PADDING(1), PING, PING, PADDING(7), CRYPTO(offset 0), CRYPTO(offset
 * 1048), PING, PADDING(82), PING, CRYPTO(offset 1098), PING, PING, PADDING(39), CRYPTO(offset 36),
 * PING, CRYPTO(offset 1216), PADDING(84). The next connection's is different again.
 * <p>
 * This is QUICHE's {@code QuicChaosProtector} and its purpose is anti-ossification: middleboxes that
 * learned to expect a ClientHello at a fixed place in a fixed shape break when the shape moves, so
 * the shape is moved deliberately, every time. Reproducing it is therefore not a matter of copying a
 * layout - there is no layout to copy, which is why two captures of the same browser disagree - but
 * of running the same four steps with the same distributions:
 * <pre>
 *   SplitCryptoFrame();   // split into 2..10 more CRYPTO frames at random points
 *   AddPingFrames();      // add 2..10 PING frames
 *   SpreadPadding();      // insert random runs of PADDING before frames, remainder at the end
 *   ReorderFrames();      // walk backwards, swapping each frame with a random earlier one
 * </pre>
 * <p>
 * <b>Only half of what Chrome does.</b> This scrambles a packet that has padding to spend, and kwik
 * fills its first Initial packet with CRYPTO to the brim - so on a ClientHello that spans two packets,
 * which a browser's always does, the second is scrambled and the first is left as one CRYPTO frame.
 * That is the packet a fingerprinter looks at first.
 * <p>
 * Chrome avoids it by dividing the ClientHello differently, in QUICHE's
 * {@code QuicPacketCreator::MultiPacketChaosProtect}: the first packet gets the first 55 to 86 bytes
 * of the ClientHello <em>and its tail</em>, and the middle goes into the packets after it, so that
 * every packet keeps room to be scrambled and a reader is forced to reassemble several of them. The
 * capture in docs/captures/chrome-152-quic-initial.pcapng shows it plainly: a 1955 byte ClientHello
 * split 975 and 980, the first packet holding offsets 0-68 and 1216-1955. Doing that here means
 * changing how kwik divides crypto data across packets, which is a separate piece of work.
 * <p>
 * It is off unless a profile asks for it. Chrome's QUIC is QUICHE and so is Chrome for Android's;
 * Firefox's is neqo and Safari's is Apple's own, and neither does this. Doing it for every profile
 * would make those two look like Chrome in the one place they are most easily told apart.
 */
public class InitialPacketChaosProtector {

    private static final int MIN_ADDED_CRYPTO_FRAMES = 2;
    private static final int MAX_ADDED_CRYPTO_FRAMES = 10;
    private static final int MIN_ADDED_PING_FRAMES = 2;
    private static final int MAX_ADDED_PING_FRAMES = 10;

    private final Version version;
    private final Random random;

    private final List<QuicFrame> frames = new ArrayList<>();
    private int remainingPaddingBytes;
    private long cryptoEndOffset;
    private int cryptoDataLength;

    public InitialPacketChaosProtector(Version version, Random random) {
        this.version = version;
        this.random = random;
    }

    /**
     * Rewrites the packet's frames into an equivalent scrambled set of the same total size.
     * <p>
     * "Equivalent" is the whole contract: the CRYPTO frames still carry the same bytes at the same
     * offsets, so a peer reassembles the identical message, and the padding taken up by the added
     * frame headers and PINGs is deducted from the padding so the packet does not grow.
     *
     * @return false when the packet is not one this can scramble, in which case it is left untouched
     */
    public boolean protect(QuicPacket packet) {
        int sizeBefore = totalFrameLength(packet.getFrames());
        if (!ingest(packet.getFrames())) {
            return false;
        }
        splitCryptoFrames();
        addPingFrames();
        spreadPadding();
        reorderFrames();

        /*
         * The packet must come out exactly as large as it went in: an Initial is padded to 1200 bytes
         * because RFC 9000 section 14.1 requires it, and every byte the added frame headers take was
         * supposed to have been deducted from the padding. If the arithmetic here and the serializer's
         * ever disagree the result is a packet of the wrong size, which is not something to discover
         * on the wire, so it is checked rather than trusted.
         */
        int sizeAfter = totalFrameLength(frames);
        if (sizeAfter != sizeBefore) {
            throw new IllegalStateException("chaos protection changed the packet from " + sizeBefore
                    + " to " + sizeAfter + " bytes of frames");
        }

        packet.getFrames().clear();
        packet.getFrames().addAll(frames);
        return true;
    }

    private static int totalFrameLength(List<QuicFrame> frames) {
        int total = 0;
        for (QuicFrame frame : frames) {
            total += frame.getFrameLength();
        }
        return total;
    }

    /**
     * Takes the frames apart into the CRYPTO frames to scramble and the padding budget to spend on
     * doing it. A packet without both is left alone: with no padding there is nothing to pay for the
     * extra frame headers with, and the point is a packet that stays exactly as large as it was.
     */
    private boolean ingest(List<QuicFrame> packetFrames) {
        boolean hasCrypto = false;
        for (QuicFrame frame : packetFrames) {
            if (frame instanceof Padding) {
                remainingPaddingBytes += frame.getFrameLength();
            }
            else {
                if (frame instanceof CryptoFrame) {
                    hasCrypto = true;
                    CryptoFrame crypto = (CryptoFrame) frame;
                    cryptoEndOffset = Math.max(cryptoEndOffset, crypto.getOffset() + crypto.getLength());
                    cryptoDataLength += crypto.getLength();
                }
                frames.add(frame);
            }
        }
        return hasCrypto && remainingPaddingBytes > 0;
    }

    /**
     * Splits the CRYPTO frames at random points, appending each new piece at the end so that the
     * pieces end up out of order once the frames are shuffled. Each split costs one more frame header,
     * which is taken out of the padding budget - so the packet carries the same bytes in the same
     * total size, just cut differently.
     */
    private void splitCryptoFrames() {
        // What one more frame may cost at worst: the header for the highest offset and the full length.
        int maxOverheadOfOneMoreFrame = cryptoFrameOverhead(cryptoEndOffset, cryptoDataLength);
        int framesToAdd = MIN_ADDED_CRYPTO_FRAMES
                + random.nextInt(MAX_ADDED_CRYPTO_FRAMES + 1 - MIN_ADDED_CRYPTO_FRAMES);
        for (int i = 0; i < framesToAdd; i++) {
            if (remainingPaddingBytes < maxOverheadOfOneMoreFrame) {
                break;
            }
            int index = random.nextInt(frames.size());
            if (!(frames.get(index) instanceof CryptoFrame)) {
                continue;
            }
            CryptoFrame toSplit = (CryptoFrame) frames.get(index);
            byte[] data = toSplit.getStreamData();
            if (data.length <= 1) {
                continue;
            }

            int keptLength = 1 + random.nextInt(data.length - 1);
            long movedOffset = toSplit.getOffset() + keptLength;
            int oldOverhead = cryptoFrameOverhead(toSplit.getOffset(), data.length);

            frames.set(index, new CryptoFrame(version, toSplit.getOffset(),
                    Arrays.copyOfRange(data, 0, keptLength)));
            frames.add(new CryptoFrame(version, movedOffset,
                    Arrays.copyOfRange(data, keptLength, data.length)));

            // Two headers now where there was one; the difference comes out of the padding.
            remainingPaddingBytes -= cryptoFrameOverhead(movedOffset, data.length - keptLength);
            remainingPaddingBytes -= cryptoFrameOverhead(toSplit.getOffset(), keptLength);
            remainingPaddingBytes += oldOverhead;
        }
    }

    private void addPingFrames() {
        if (remainingPaddingBytes == 0) {
            return;
        }
        int pings = Math.min(MIN_ADDED_PING_FRAMES
                + random.nextInt(MAX_ADDED_PING_FRAMES + 1 - MIN_ADDED_PING_FRAMES), remainingPaddingBytes);
        for (int i = 0; i < pings; i++) {
            frames.add(new PingFrame());
        }
        remainingPaddingBytes -= pings;
    }

    /**
     * Inserts a run of padding of random length before each frame, and whatever is left over at the
     * end, so that every byte of the original padding is still there and the packet keeps its size.
     */
    private void spreadPadding() {
        for (int i = 0; i < frames.size(); i++) {
            int paddingHere = random.nextInt(remainingPaddingBytes + 1);
            if (paddingHere <= 0) {
                continue;
            }
            frames.add(i, new Padding(paddingHere));
            i++;   // Skip over the padding just added.
            remainingPaddingBytes -= paddingHere;
        }
        if (remainingPaddingBytes > 0) {
            frames.add(new Padding(remainingPaddingBytes));
            remainingPaddingBytes = 0;
        }
    }

    /** Walks the array backwards and swaps each frame with a random earlier one. */
    private void reorderFrames() {
        for (int i = frames.size() - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            QuicFrame swap = frames.get(i);
            frames.set(i, frames.get(j));
            frames.set(j, swap);
        }
    }

    /** The bytes a CRYPTO frame costs beyond its data: the type, the offset and the length. */
    private static int cryptoFrameOverhead(long offset, int length) {
        return 1 + VariableLengthInteger.bytesNeeded(offset) + VariableLengthInteger.bytesNeeded(length);
    }
}
