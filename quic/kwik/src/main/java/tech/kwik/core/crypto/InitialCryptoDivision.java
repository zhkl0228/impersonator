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
     * @param clientHello the whole first flight, which a division may read: neqo's cuts it at the
     *                    server name, so where the pieces fall depends on what is in it
     * @param packetCapacity how many bytes of CRYPTO frame payload one Initial packet can hold
     * @return the pieces in wire order, or an empty list to leave the division to the sender
     */
    List<Piece> divide(byte[] clientHello, int packetCapacity);

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
        public List<Piece> divide(byte[] clientHello, int packetCapacity) {
            int totalLength = clientHello.length;
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

    /**
     * A fixed limit on how much of the ClientHello one Initial packet carries, which is what Safari
     * does.
     * <p>
     * Where Chrome moves the message about and Firefox cuts it at the server name, Safari sends it in
     * order and simply stops early: its first Initial carries 999 bytes of CRYPTO and leaves the rest
     * of the packet empty, and the remainder follows in the next one. The packet is still padded to
     * the full datagram - Safari pads from the inside like Chrome - so what a server sees is a first
     * Initial with one CRYPTO frame and 162 bytes of PADDING behind it, where filling the packet would
     * leave none.
     * <p>
     * 999 is a constant and not a share of the message, which took four connections to establish:
     * <pre>
     *   capture                          ClientHello  first packet  padding
     *   safari-26-quic.json              fresh, 11 extensions   999      162
     *   safari-26-quic-resumed.json      resumed, 13 extensions 999      162
     *   safari-26-ios-quic.json          iOS, fresh             999      162
     *   safari-26-quic-initial-2.pcapng  1485 bytes             999      162
     * </pre>
     * The resumed ClientHello is longer than the fresh one - it carries a pre_shared_key and its
     * binder - and the first packet is the same 999 bytes all the same, which is what rules out every
     * rule that divides the message in proportion. The last row is a full packet capture, so its
     * numbers are read off the wire rather than inferred: CRYPTO[0,999) then PADDING x162, and
     * CRYPTO[999,1485) then PADDING x674 in the packet after it.
     * <p>
     * What 999 is derived from is not known. With the 8 byte Destination Connection ID and one byte
     * packet number Safari always sends, a 1200 byte datagram leaves 1165 bytes of payload, so the
     * 999 byte frame and its 4 byte header leave exactly the 162 that is observed - but why Safari
     * stops there rather than at 1161 is a question no capture here answers, so this reproduces the
     * number rather than a reason for it.
     * <p>
     * Only the first packet's limit is evidenced. The second packet of every capture is well under it
     * - 486 bytes - so whether a third would start at 1998 is not something these samples say; they
     * say the remainder follows in order, and that is what this does.
     */
    final class FixedChunks implements InitialCryptoDivision {

        private final int limit;

        public FixedChunks(int limit) {
            if (limit <= 0) {
                throw new IllegalArgumentException("a chunk limit must be positive, got " + limit);
            }
            this.limit = limit;
        }

        @Override
        public List<Piece> divide(byte[] clientHello, int packetCapacity) {
            List<Piece> pieces = new ArrayList<>(2);
            if (clientHello.length <= packetCapacity) {
                // One packet holds it, so there is nothing to divide. Safari's ClientHello never fits -
                // its post-quantum key share alone is over 1200 bytes - so there is no capture of what
                // it would do with a small one, and a division invented for that case would put a
                // layout on the wire that nothing supports.
                return pieces;
            }
            for (int offset = 0; offset < clientHello.length; offset += limit) {
                pieces.add(new Piece(offset, Math.min(limit, clientHello.length - offset)));
            }
            return pieces;
        }
    }

    /**
     * neqo's SNI slicing, which is what Firefox does.
     * <p>
     * Where QUICHE moves the ClientHello about to keep middleboxes from assuming a shape, neqo aims at
     * one field: it cuts the message <em>through the middle of the server name</em> and sends the two
     * halves in the wrong order, so that neither datagram holds a whole hostname and reading one out of
     * the first packet stops working. From {@code neqo-transport/src/crypto.rs}:
     * <pre>
     *   if sni_slicing &amp;&amp; offset == 0 {
     *       if let Some(sni) = find_sni(data) {
     *           // Cut the crypto data in two at the midpoint of the SNI
     *           let mid = sni.start + (sni.end - sni.start) / 2;
     *           let (left, right) = data.split_at(mid);
     *           // ...swap the chunks.
     * </pre>
     * {@code find_sni} returns the host name bytes themselves, so the cut lands halfway through the
     * name. The two captured Firefox 155 connections in docs/captures/firefox-155-quic-initial.pcapng
     * agree with that to the byte, and are a good illustration of why the cut moves:
     * <pre>
     *   ClientHello  first packet     second packet   cut at  tail begins at
     *   1912         847 + 109 = 956  956             109     1065
     *   1904         466 + 486 = 952  952             486     1438
     * </pre>
     * Same host and so the same host name both times, cut in a completely different place - because
     * Firefox permutes its ClientHello extensions, so the server_name sits at a different offset every
     * connection. The two behaviours explain each other, and neither could be reproduced by copying a
     * layout.
     * <p>
     * The halves are exact, {@code total / 2} each, which is neqo's {@code limit_chunks} filling the
     * packets evenly - Chrome's are five bytes apart, and that difference alone tells the two apart.
     * The first packet carries the <em>end</em> of the right chunk and then the whole left chunk; what
     * is left of the right chunk goes in the second.
     * <p>
     * No PING frames and no padding to spread: Firefox's first Initial is two CRYPTO frames and nothing
     * else, which is why this is a division on its own and not a companion to the frame scrambler.
     */
    final class NeqoSniSlicing implements InitialCryptoDivision {

        @Override
        public List<Piece> divide(byte[] clientHello, int packetCapacity) {
            List<Piece> pieces = new ArrayList<>(4);
            int total = clientHello.length;
            int mid = serverNameMidpoint(clientHello);
            if (mid <= 0 || mid >= total || packetCapacity <= 0) {
                // No server name to cut through. neqo writes the whole flight in one chunk then, and
                // so does the sender when it is given no pieces.
                return pieces;
            }
            /*
             * neqo's limit, from the call site of limit_chunks:
             *   let packets_needed = data.len().div_ceil(builder.limit());
             *   let limit = data.len() / packets_needed;
             * which is what makes the packets evenly filled rather than the first one full. Chrome's
             * halves differ by five bytes and Firefox's are equal, and that alone tells them apart.
             */
            int packetsNeeded = (total + packetCapacity - 1) / packetCapacity;
            int limit = total / packetsNeeded;

            int leftOffset = 0, leftLength = mid;
            int rightOffset = mid, rightLength = total - mid;
            if (leftLength + rightLength <= limit) {
                // Both fit, so the name is not split across packets - but it is still in two CRYPTO
                // frames in the wrong order, which is neqo's comment on this branch exactly.
            }
            else if (leftLength <= limit) {
                // "So send from the *end* of right, so that the second half of the SNI is in another
                // packet."
                int dropped = rightLength + leftLength - limit;
                rightOffset += dropped;
                rightLength -= dropped;
            }
            else if (rightLength <= limit) {
                // "The SNI begins at the end of left, so send the beginning of it in this packet."
                leftLength = limit - rightLength;
            }
            else {
                leftLength = limit / 2;
                rightLength = limit / 2;
            }

            // Right first, then left: the swap is the whole point, and it is what puts the tail of the
            // ClientHello at the front of the first datagram.
            pieces.add(new Piece(rightOffset, rightLength));
            pieces.add(new Piece(leftOffset, leftLength));
            // Whatever the first packet did not take, in order, which is how neqo sends the rest: the
            // slicing only applies at offset zero.
            addGap(pieces, leftOffset + leftLength, rightOffset);
            addGap(pieces, rightOffset + rightLength, total);
            return pieces;
        }

        private static void addGap(List<Piece> pieces, int from, int to) {
            if (to > from) {
                pieces.add(new Piece(from, to - from));
            }
        }

        /**
         * The middle of the host name in a ClientHello, or -1 when it carries none.
         * <p>
         * This walks the message rather than searching it, so it can only answer for a ClientHello it
         * actually understood: anything that does not parse as one returns -1 and the caller sends the
         * flight the ordinary way, which is also what neqo does when find_sni finds nothing. A wrong
         * offset here would cut the message somewhere neqo never cuts it, which is worse than not
         * cutting it at all.
         */
        static int serverNameMidpoint(byte[] hello) {
            try {
                int p = 4;                      // handshake type and 24 bit length
                p += 2;                         // legacy_version
                p += 32;                        // random
                p += 1 + (hello[p] & 0xff);     // legacy_session_id
                p += 2 + uint16(hello, p);      // cipher_suites
                p += 1 + (hello[p] & 0xff);     // legacy_compression_methods
                int extensionsEnd = p + 2 + uint16(hello, p);
                p += 2;
                while (p < extensionsEnd) {
                    int type = uint16(hello, p);
                    int length = uint16(hello, p + 2);
                    if (type == 0) {            // server_name
                        // ServerNameList length, then the name_type and host_name length that
                        // find_sni skips to reach the name itself.
                        int start = p + 4 + 2 + 3;
                        int end = start + uint16(hello, p + 4) - 3;
                        return end <= hello.length && end > start ? start + (end - start) / 2 : -1;
                    }
                    p += 4 + length;
                }
                return -1;
            }
            catch (RuntimeException malformed) {
                // Not a ClientHello this understands. Saying so is the whole point; guessing an offset
                // would put a cut on the wire that no capture supports.
                return -1;
            }
        }

        private static int uint16(byte[] data, int offset) {
            return ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
        }
    }
}
