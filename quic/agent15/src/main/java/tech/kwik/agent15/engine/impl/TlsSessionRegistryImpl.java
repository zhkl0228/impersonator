/*
 * Copyright © 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Agent15, an implementation of TLS 1.3 in Java.
 *
 * Agent15 is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Agent15 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.TlsSession;
import tech.kwik.agent15.engine.TlsSessionRegistry;
import tech.kwik.agent15.extension.ClientHelloPreSharedKeyExtension;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;


public class TlsSessionRegistryImpl implements TlsSessionRegistry {

    private static final int DEFAULT_TICKET_LIFETIME_HOURS = 24;
    private static final int DEFAULT_TICKET_LENGTH = 128 / 8;
    private static final int DEFAULT_MAX_REGISTRY_SIZE = 1000;  // Approx 400K

    private Random randomGenerator = new SecureRandom();
    private Map<BytesKey, Session> sessions = new ConcurrentHashMap<>();
    private int ticketLifeTimeInSeconds;
    private volatile boolean closed;
    private ScheduledExecutorService scheduledExecutorService;
    private final int maxRegistrySize;

    public TlsSessionRegistryImpl() {
        this((int) TimeUnit.HOURS.toSeconds(DEFAULT_TICKET_LIFETIME_HOURS), DEFAULT_MAX_REGISTRY_SIZE);
    }

    public TlsSessionRegistryImpl(int ticketLifeTimeInSeconds, int maxSize) {
        this.ticketLifeTimeInSeconds = ticketLifeTimeInSeconds;
        this.maxRegistrySize = maxSize;
        scheduledExecutorService = Executors.newSingleThreadScheduledExecutor();
        scheduledExecutorService.scheduleAtFixedRate(this::cleanupExpiredPsks, 1, 1, TimeUnit.MINUTES);
    }

    @Override
    public NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite cipher, TlsState tlsState, String applicationProtocol) {
        return createNewSessionTicketMessage(ticketNonce, cipher, tlsState, applicationProtocol, null, null);
    }

    @Override
    public NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite cipher, TlsState tlsState, String applicationProtocol, Long maxEarlyDataSize, byte[] data) {
        if (! closed && !full()) {
            byte[] psk = tlsState.computePSK(new byte[]{ticketNonce});
            long ageAdd = randomGenerator.nextLong();
            byte[] ticketId = new byte[DEFAULT_TICKET_LENGTH];
            randomGenerator.nextBytes(ticketId);
            Instant expiry = Instant.now().plusMillis(TimeUnit.SECONDS.toMillis(ticketLifeTimeInSeconds));
            sessions.put(new BytesKey(ticketId), new Session(ticketId, ticketNonce, ageAdd, psk, cipher, Instant.now(), expiry, applicationProtocol, data));
            if (maxEarlyDataSize != null) {
                return new NewSessionTicketMessage(ticketLifeTimeInSeconds, ageAdd, new byte[]{ticketNonce}, ticketId, maxEarlyDataSize);
            }
            else {
                return new NewSessionTicketMessage(ticketLifeTimeInSeconds, ageAdd, new byte[]{ticketNonce}, ticketId);
            }
        }
        else {
            return null;
        }
    }

    private boolean full() {
        return sessions.size() >= maxRegistrySize;
    }

    @Override
    public Integer selectIdentity(List<ClientHelloPreSharedKeyExtension.PskIdentity> identities, TlsConstants.CipherSuite cipher) {
        for (int i = 0; i < identities.size(); i++) {
            BytesKey key = new BytesKey(identities.get(i).getIdentity());
            Session candidateSession = sessions.get(key);
            if (candidateSession != null && candidateSession.expiry.isAfter(Instant.now())) {
                // Note that this condition is (probably) stronger than what the specification mandates:
                // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
                // "Each PSK is associated with a single Hash algorithm. For PSKs established via the ticket mechanism
                //  (Section 4.6.1), this is the KDF Hash algorithm on the connection where the ticket was established."
                // "The server MUST ensure that it selects a compatible PSK (if any) and cipher suite."
                // "When session resumption is the primary use case of PSKs, the most straightforward way to implement the
                //  PSK/cipher suite matching requirements is to negotiate the cipher suite first and then exclude any incompatible PSKs."
                if (candidateSession.cipher == cipher) {
                    return i;
                }
            }
            // "Any unknown PSKs (e.g., ones not in the PSK database or encrypted with an unknown key) SHOULD simply be ignored."
        }
        return null;
    }

    @Override
    public TlsSession useSession(ClientHelloPreSharedKeyExtension.PskIdentity pskIdentity) {
        // Remove session immediately, to avoid psk being used more than once.
        return sessions.remove(new BytesKey(pskIdentity.getIdentity()));
    }

    @Override
    public byte[] peekSessionData(ClientHelloPreSharedKeyExtension.PskIdentity pskIdentity) {
        return sessions.get(new BytesKey(pskIdentity.getIdentity())).getData();
    }

    @Override
    public void shutdown() {
        closed = true;
        scheduledExecutorService.shutdown();
        sessions.clear();
    }

    void cleanupExpiredPsks() {
        Instant now = Instant.now();
        List<BytesKey> expired = sessions.entrySet().stream()
                .filter(entry -> entry.getValue().expiry.isBefore(now))
                .map(entry -> entry.getKey())
                .collect(Collectors.toList());
        expired.forEach(key -> sessions.remove(key));
    }

    private class Session implements TlsSession {
        // Rough size estimate
        //  - Object header: 16 bytes
        //  - ticketId (byte[16]): 16 + 16 = 32 bytes (array header + data)
        //  - ticketNonce (byte): 1 byte (padded to 8)
        //  - addAdd (long): 8 bytes
        //  - psk (byte[32] for SHA-256, or byte[48] for SHA-384): ~16 + 48 = 64 bytes
        //  - cipher (enum ref): 4 bytes
        //  - created (Instant): ~24 bytes
        //  - expiry (Instant): ~24 bytes
        //  - applicationProtocol (String, e.g. "h3"): ~48 bytes
        //  - data (byte[], typically null): 4 bytes
        //  - Field padding/alignment: ~8 bytes
        //  Map entry overhead:
        //  - BytesKey wrapper: 16 + 4 + 16 + 16 = ~52 bytes (header + ref + array header + data)
        //  - ConcurrentHashMap.Node: ~48 bytes
        //  Total: roughly 350-400 bytes per session.
        final byte[] ticketId;
        final byte ticketNonce;
        final long addAdd;
        final byte[] psk;
        final TlsConstants.CipherSuite cipher;
        final Instant created;
        private final Instant expiry;
        final String applicationProtocol;
        private final byte[] data;

        public Session(byte[] ticketId, byte ticketNonce, long addAdd, byte[] psk, TlsConstants.CipherSuite cipher, Instant created, Instant expiry, String applicationProtocol, byte[] data) {
            this.ticketId = ticketId;
            this.ticketNonce = ticketNonce;
            this.addAdd = addAdd;
            this.psk = psk;
            this.cipher = cipher;
            this.created = created;
            this.expiry = expiry;
            this.applicationProtocol = applicationProtocol;
            this.data = data;
        }

        @Override
        public byte[] getPsk() {
            return psk;
        }

        @Override
        public String getApplicationLayerProtocol() {
            return applicationProtocol;
        }

        @Override
        public byte[] getData() {
            return data;
        }
    }

    private class BytesKey {
        private final byte[] data;

        public BytesKey(byte[] data) {
            this.data = data;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            BytesKey other = (BytesKey) o;
            return Arrays.equals(data, other.data);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(data);
        }
    }
}
