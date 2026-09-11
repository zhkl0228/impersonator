/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to scramble Initial
 * packets the way Chrome does; see quic/kwik/UPSTREAM.md.
 */
package tech.kwik.core.send;

import tech.kwik.core.ack.AckGenerator;
import tech.kwik.core.ack.GlobalAckGenerator;
import tech.kwik.core.cid.ConnectionIdProvider;
import tech.kwik.core.common.EncryptionLevel;
import tech.kwik.core.common.PnSpace;
import tech.kwik.core.frame.Padding;
import tech.kwik.core.packet.InitialPacket;

import java.security.SecureRandom;
import java.util.Random;
import tech.kwik.core.frame.PathResponseFrame;
import tech.kwik.core.impl.VersionHolder;

import java.net.InetSocketAddress;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static tech.kwik.core.common.EncryptionLevel.Handshake;
import static tech.kwik.core.common.EncryptionLevel.Initial;
import static tech.kwik.core.common.EncryptionLevel.ZeroRTT;

/**
 * Assembles QUIC packets for sending. The term "global" refers to the fact that this packet assembler can assemble
 * packets of various encryption levels, even at the same time (which can happen during connection handshake).
 */
public class GlobalPacketAssembler {

    private SendRequestQueue[] sendRequestQueue;
    private volatile PacketAssembler[] packetAssembler = new PacketAssembler[EncryptionLevel.values().length];
    private volatile EncryptionLevel[] enabledLevels;
    private final VersionHolder quicVersion;
    /**
     * Where the padding that brings a datagram up to its minimum size goes; see {@link PaddingMode}.
     * <p>
     * Not a constant, because it is a fingerprint: the two Initial packets of Firefox's first flight
     * end at 1014 and 1010 bytes inside a 1252 byte datagram, the rest of it zeroes outside the QUIC
     * packet, while Chrome's and Safari's packets fill their datagrams to the last byte with PADDING
     * frames. Read off docs/captures/*-quic-initial.pcapng, and it agrees with what the fingerprint
     * endpoint reports: Chrome's first Initial has a padding_length of 210 and Firefox's has no
     * padding at all.
     */
    private volatile PaddingMode paddingMode;
    private final Random random = new SecureRandom();
    private volatile boolean chaosProtection;

    /**
     * The size a datagram carrying an Initial packet is padded to. RFC 9000 section 14.1 requires at
     * least 1200 and every client picks its own number above that, which is one of the things a QUIC
     * client is recognized by: Chrome sends 1250, QUICHE's kDefaultMaxPacketSize, and Safari sends
     * the bare 1200.
     */
    private volatile int initialDatagramSize = 1200;

    public void setInitialDatagramSize(int initialDatagramSize) {
        if (initialDatagramSize < 1200) {
            throw new IllegalArgumentException("RFC 9000 section 14.1 requires at least 1200 bytes, got "
                    + initialDatagramSize);
        }
        this.initialDatagramSize = initialDatagramSize;
    }


    public GlobalPacketAssembler(VersionHolder quicVersion, SendRequestQueue[] sendRequestQueues, GlobalAckGenerator globalAckGenerator,
                                 ConnectionIdProvider connectionIdProvider) {
        this.quicVersion = Objects.requireNonNull(quicVersion);
        this.sendRequestQueue = Objects.requireNonNull(sendRequestQueues);
        Objects.requireNonNull(globalAckGenerator);
        Objects.requireNonNull(connectionIdProvider);

        PacketNumberGenerator appSpacePnGenerator = new PacketNumberGenerator();

        Arrays.stream(EncryptionLevel.values()).forEach(level -> {
            int levelIndex = level.ordinal();
            AckGenerator ackGenerator =
                    (level != ZeroRTT)?
                            globalAckGenerator.getAckGenerator(level.relatedPnSpace()):
                            // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-17.2.3
                            // "... a client cannot send an ACK frame in a 0-RTT packet, ..."
                            new NullAckGenerator();
            switch (level) {
                case ZeroRTT:
                case App:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, sendRequestQueue[levelIndex], ackGenerator,
                            connectionIdProvider, appSpacePnGenerator);
                    break;
                case Initial:
                    packetAssembler[levelIndex] = new InitialPacketAssembler(quicVersion, sendRequestQueue[levelIndex], ackGenerator, connectionIdProvider);
                    break;
                default:
                    packetAssembler[levelIndex] = new PacketAssembler(quicVersion, level, sendRequestQueue[levelIndex], ackGenerator,
                            connectionIdProvider);
            }
        });

        enabledLevels = new EncryptionLevel[] { Initial, ZeroRTT, Handshake };

        String paddingModeProp = System.getProperty("tech.kwik.padding-mode", "inside");
        paddingMode = "outside".equalsIgnoreCase(paddingModeProp) ? PaddingMode.OUTSIDE : PaddingMode.INSIDE;
    }

    /**
     * Assembles packets for sending in one datagram. The total size of the QUIC packets returned will never exceed
     * max packet size and for packets not containing probes, it will not exceed the remaining congestion window size.
     * The given client address is used to determine the connection ID to use as destination connection ID. As clients
     * can migrate to a new address (and servers can't), only the client address determines which connection ID to use.
     * When a connection is migrating to a new address, both peers must use a new connection ID to avoid the new path
     * can be correlated with the old path.
     *
     * @param remainingCwndSize
     * @param maxDatagramSize
     * @param clientAddress  the address from (client role) or to (server role) which the datagram will be sent.
     * @return
     */
    public AssembledDatagram assemble(int remainingCwndSize, int maxDatagramSize, InetSocketAddress clientAddress) {
        List<SendItem> packets = new ArrayList<>();
        int size = 0;
        boolean hasInitial = false;
        boolean hasPathResponse = false;

        int minPacketSize = 19;  // Is mininum size for short header packet, long header packet is at least 24
        int remaining = Integer.min(remainingCwndSize, maxDatagramSize);

        for (EncryptionLevel level: enabledLevels) {
            PacketAssembler assembler = this.packetAssembler[level.ordinal()];
            if (assembler != null) {
                Optional<SendItem> item = assembler.assemble(remaining, maxDatagramSize - size, clientAddress);
                if (item.isPresent()) {
                    packets.add(item.get());
                    int packetSize = item.get().getPacket().estimateLength(0);
                    size += packetSize;
                    remaining -= packetSize;
                    if (level == Initial) {
                        hasInitial = true;
                    }
                    if (item.get().getPacket().getFrames().stream().anyMatch(f -> f instanceof PathResponseFrame)) {
                        hasPathResponse = true;
                    }
                }
                if (remaining < minPacketSize && (maxDatagramSize - size) < minPacketSize) {
                    // Trying a next level to produce a packet is useless
                    break;
                }
            }
        }

        int minDatagramSize = 0;

        /*
         * Never past what this datagram may be: the datagram buffer in SenderImpl.send is exactly
         * maxDatagramSize bytes, so padding beyond it is a BufferOverflowException on the sender
         * thread. It could not happen while this was the hardcoded 1200 that RFC 9000 section 14.1
         * requires every endpoint to accept, and it can once a profile asks for 1250 or 1252: the
         * peer's max_udp_payload_size may be as low as 1200, registerMaxUdpPayloadSize lowers
         * maxPacketSize to it, and an Initial packet can still be sent afterwards - an ACK for the
         * server's Initials, before the client's first Handshake packet discards the level.
         *
         * The same Integer.min the PATH_RESPONSE case below has always had, for the same reason.
         */
        int requiredInitialSize = Integer.min(initialDatagramSize, maxDatagramSize);

        if (hasInitial && size < requiredInitialSize) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-14.1
            // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at least the smallest
            //  allowed maximum datagram size of 1200 bytes by adding PADDING frames to the Initial packet or by coalescing
            //  the Initial packet; see Section 12.2."
            // "Similarly, a server MUST expand the payload of all UDP datagrams carrying ack-eliciting Initial packets
            //  to at least the smallest allowed maximum datagram size of 1200 bytes."
            if (paddingMode == PaddingMode.INSIDE) {
                size += addPadding(packets, size, requiredInitialSize);
            }
            else {
                minDatagramSize = requiredInitialSize;
            }
        }

        if (hasPathResponse && size < 1200) {
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.1
            // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit
            //  sending a datagram of this size."
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2.2
            // "An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least the smallest allowed
            //  maximum datagram size of 1200 bytes."
            // "However, an endpoint MUST NOT expand the datagram containing the PATH_RESPONSE if the resulting data
            //  exceeds the anti-amplification limit."
            int required = Integer.min(1200, maxDatagramSize);
            if (paddingMode == PaddingMode.INSIDE) {
                size += addPadding(packets, size, required);
            }
            else {
                minDatagramSize = Integer.max(minDatagramSize, required);
            }
        }

        if (hasInitial && chaosProtection) {
            /*
             * After the padding, because the padding is what pays for the extra frame headers, and
             * only for Initial packets, which is the flight Chrome scrambles. See
             * InitialPacketChaosProtector.
             */
            for (SendItem item : packets) {
                if (item.getPacket() instanceof InitialPacket) {
                    new InitialPacketChaosProtector(quicVersion.getVersion(), random).protect(item.getPacket());
                }
            }
        }

        return new AssembledDatagram(packets, minDatagramSize);
    }

    /**
     * Whether Initial packets are scrambled the way Chrome scrambles them; see
     * {@link InitialPacketChaosProtector}, which explains why this is a profile's choice and not
     * something to do for every client.
     */
    public void setChaosProtection(boolean chaosProtection) {
        this.chaosProtection = chaosProtection;
    }

    /** See {@link #paddingMode}; null keeps what the system property asked for. */
    public void setPaddingMode(PaddingMode paddingMode) {
        if (paddingMode != null) {
            this.paddingMode = paddingMode;
        }
    }

    protected int addPadding(List<SendItem> packets, int currentEstimatedSize, int requiredMinimumSize) {
        assert packets.size() > 0;
        final int proposedPadding = requiredMinimumSize - currentEstimatedSize;

        int expectedSizeWithPadding =
                // It doesn't matter to which packet the padding is added, take the first (that is guaranteed to exist)
                packets.get(0).getPacket().estimateLength(proposedPadding) +
                packets.stream()  // And add the size of the coalesced packets (if any)
                        .skip(1)
                        .map(item -> item.getPacket())
                        .mapToInt(p -> p.estimateLength(0))
                        .sum();

        int requiredPadding;
        if (expectedSizeWithPadding > requiredMinimumSize) {
            // Can happen due to padding causing the length field of a long header packet to increase (by 1)
            requiredPadding = proposedPadding - (expectedSizeWithPadding - requiredMinimumSize);
        }
        else if (expectedSizeWithPadding < requiredMinimumSize) {
            // Can happen with very small packets, that already had padding to have minimum size (required by AEAD encryption):
            // when more padding is added, the "initial" padding is no longer needed, causing the packet to shrink
            requiredPadding = proposedPadding + (requiredMinimumSize - expectedSizeWithPadding);
        }
        else {
            requiredPadding = proposedPadding;
        }

        if (requiredPadding > 0) {
            packets.stream()
                    .map(item -> item.getPacket())
                    .findFirst()
                    // It doesn't matter to which packet the padding is added, take the first (that is guaranteed to exist)
                    .ifPresent(packet -> packet.addFrame(new Padding(requiredPadding)));
            return requiredPadding;
        }
        else {
            return 0;
        }
    }

    public Optional<Instant> nextDelayedSendTime() {
        return Arrays.stream(enabledLevels)
                .map(level -> sendRequestQueue[level.ordinal()])
                .map(q -> q.nextDelayedSend())
                .filter(Objects::nonNull)     // Filter after mapping because value can become null during iteration
                .findFirst();
    }

    public void stop(PnSpace pnSpace) {
        packetAssembler[pnSpace.relatedEncryptionLevel().ordinal()].stop(assembler -> {
            packetAssembler[pnSpace.relatedEncryptionLevel().ordinal()] = null;
        });
    }

    public void setInitialToken(byte[] token) {
        ((InitialPacketAssembler) packetAssembler[Initial.ordinal()]).setInitialToken(token);
    }

    public void enableAppLevel() {
        enabledLevels = EncryptionLevel.values();
    }

}
