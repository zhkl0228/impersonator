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
package tech.kwik.core.crypto;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * How a ClientHello too large for one Initial packet is divided between them.
 * <p>
 * kwik fills each packet from the front until the data runs out, which no browser does. What they do
 * instead differs per browser and is visible to anyone who looks at the first datagram, so it belongs
 * to the profile rather than to the connection.
 * <p>
 * A division is a list of pieces in the order they go on the wire, each an offset into the ClientHello
 * and a length; the sender packs them into packets in that order. Sequential division - piece 0 of
 * whatever fits, then the next - is what kwik already does and is what a null division means.
 */
public interface InitialCryptoDivision {

    /**
     * @param totalLength the whole ClientHello
     * @param packetCapacity how many bytes of CRYPTO frame payload one Initial packet can hold
     * @return the pieces in wire order, or an empty list to leave the division to the sender
     */
    List<Piece> divide(int totalLength, int packetCapacity);

    /** A run of the ClientHello, as it goes into one CRYPTO frame. */
    final class Piece {
        public final int offset;
        public final int length;

        public Piece(int offset, int length) {
            this.offset = offset;
            this.length = length;
        }

        @Override
        public String toString() {
            return "Piece[" + offset + "," + (offset + length) + ")";
        }
    }

    /**
     * QUICHE's {@code QuicPacketCreator::MultiPacketChaosProtect}, which is what Chrome does.
     * <p>
     * The first packet carries the first few dozen bytes of the ClientHello <em>and its tail</em>, and
     * the middle goes into the packet after it. A reader that expected the ClientHello to begin at the
     * start of the first datagram and continue in order finds neither, and has to reassemble both
     * packets before it can read anything - which is the point, the same anti-ossification purpose as
     * the frame scrambling that runs afterwards.
     * <p>
     * The rule is read off four captured Chrome 152 connections in
     * docs/captures/chrome-152-quic-initial.pcapng, which agree to the byte:
     * <pre>
     *   ClientHello  first packet  second packet  first frame  tail begins at
     *   1955         975           980            68           1048
     *   2163         1079          1084           81           -
     *   1947         971           976            73           1049
     * </pre>
     * So the halves are {@code (total - 5) / 2} and the remainder - the five bytes being the extra
     * CRYPTO frame header the first packet needs for carrying two runs rather than one - and the first
     * frame is 55 to 86 bytes, QUICHE's {@code kMinFirstFrameLength} of 55 plus a random value under
     * its {@code kFirstFrameLengthRandom} of 32. The tail then fills out the first packet:
     * 1955 - (975 - 68) = 1048, and 1947 - (971 - 73) = 1049, both exactly the lowest tail offset
     * observed.
     * <p>
     * Each half is left short of the packet it goes in, and that slack is what
     * {@code InitialPacketChaosProtector} spends on PING frames and runs of PADDING. Filling the packet
     * would leave it nothing to spend, which is what used to happen and why Chrome's first Initial went
     * out barely scrambled.
     */
    final class ChromeMultiPacket implements InitialCryptoDivision {

        /** QUICHE's kMinFirstFrameLength and kFirstFrameLengthRandom. */
        private static final int MIN_FIRST_FRAME_LENGTH = 55;
        private static final int FIRST_FRAME_LENGTH_RANDOM = 32;

        /** The extra CRYPTO frame header the first packet pays for carrying a head and a tail. */
        private static final int SECOND_FRAME_HEADER = 5;

        private final Random random;

        public ChromeMultiPacket(Random random) {
            this.random = random;
        }

        @Override
        public List<Piece> divide(int totalLength, int packetCapacity) {
            List<Piece> pieces = new ArrayList<>(3);
            int firstPacket = (totalLength - SECOND_FRAME_HEADER) / 2;
            int firstFrame = MIN_FIRST_FRAME_LENGTH + random.nextInt(FIRST_FRAME_LENGTH_RANDOM);
            if (totalLength <= packetCapacity || firstPacket <= firstFrame) {
                // One packet holds it, or it is so small that a head and a tail would overlap. Neither
                // is a ClientHello any browser here sends, and guessing at a shape for it would put a
                // layout on the wire that no capture supports.
                return pieces;
            }
            int tailLength = firstPacket - firstFrame;
            int tailOffset = totalLength - tailLength;

            pieces.add(new Piece(0, firstFrame));
            pieces.add(new Piece(tailOffset, tailLength));
            pieces.add(new Piece(firstFrame, tailOffset - firstFrame));
            return pieces;
        }
    }
}
