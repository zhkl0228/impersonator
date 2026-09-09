/*
 * Copyright © 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.extension;

import tech.kwik.agent15.BinderCalculator;
import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.engine.impl.TlsEngineImpl;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * TLS Pre-Shared Key Extension, ClientHello variant.
 * see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
 */
public class ClientHelloPreSharedKeyExtension extends PreSharedKeyExtension {

    private static int MINIMUM_EXTENSION_DATA_SIZE = 2 +   2 + 1 + 4 +   2 + 1 + 32;

    private List<PskIdentity> identities;
    private List<PskBinderEntry> binders;
    private int binderPosition;
    private byte[] binder;


    public ClientHelloPreSharedKeyExtension(NewSessionTicket newSessionTicket) {
        Date ticketCreationDate = newSessionTicket.getTicketCreationDate();
        long ticketAgeAdd = newSessionTicket.getTicketAgeAdd();
        byte[] sessionTicketIdentity = newSessionTicket.getSessionTicketIdentity();
        long obfuscatedTicketAge = ((new Date().getTime() - ticketCreationDate.getTime()) + ticketAgeAdd) % 0x100000000L;
        identities = List.of(new PskIdentity(sessionTicketIdentity, obfuscatedTicketAge));
        binders = new ArrayList<>();
        binders.add(new PskBinderEntry(new byte[TlsEngineImpl.hashLength(newSessionTicket.getCipher())]));
    }

    public ClientHelloPreSharedKeyExtension() {
    }

    public ClientHelloPreSharedKeyExtension parse(ByteBuffer buffer) throws DecodeErrorException {
        int startPosition = buffer.position();
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.pre_shared_key, MINIMUM_EXTENSION_DATA_SIZE);

        identities = new ArrayList<>();
        int remainingIdentitiesLength = buffer.getShort() & 0xffff;
        int remaining = extensionDataLength - 2;
        while (remainingIdentitiesLength > 0) {
            if (remaining < 2) {
                throw new DecodeErrorException("Incomplete psk identity");
            }
            int identityLength = buffer.getShort() & 0xffff;
            remaining -= 2;
            if (identityLength > remaining) {
                throw new DecodeErrorException("Incorrect identity length value");
            }
            byte[] identity = new byte[identityLength];
            buffer.get(identity);
            remaining -= identityLength;
            if (remaining < 4) {
                throw new DecodeErrorException("Incomplete psk identity");
            }
            long obfuscatedTicketAge = buffer.getInt() & 0xffffffffL;
            remaining -= 4;
            identities.add(new PskIdentity(identity, obfuscatedTicketAge));
            remainingIdentitiesLength -= (2 + identityLength + 4);
        }
        if (remainingIdentitiesLength != 0) {
            throw new DecodeErrorException("Incorrect identities length value");
        }

        binderPosition = buffer.position() - startPosition;
        binders = new ArrayList<>();
        if (remaining < 2) {
            throw new DecodeErrorException("Incomplete binders");
        }
        int bindersLength = buffer.getShort() & 0xffff;
        remaining -= 2;
        while (bindersLength > 0) {
            if (remaining < 1) {
                throw new DecodeErrorException("Incorrect binder value");
            }
            int binderLength = buffer.get() & 0xff;
            remaining -= 1;
            if (binderLength > remaining) {
                throw new DecodeErrorException("Incorrect binder length value");
            }
            if (binderLength < 32) {
                throw new DecodeErrorException("Invalid binder length");
            }
            byte[] hmac = new byte[binderLength];
            buffer.get(hmac);
            remaining -= binderLength;
            binders.add(new PskBinderEntry(hmac));
            bindersLength -= (1 + binderLength);
        }
        if (bindersLength != 0) {
            throw new DecodeErrorException("Incorrect binders length value");
        }
        if (remaining > 0) {
            throw new DecodeErrorException("Incorrect extension data length value");
        }
        if (identities.size() != binders.size()) {
            throw new DecodeErrorException("Inconsistent number of identities vs binders");
        }
        if (identities.size() == 0) {
            throw new DecodeErrorException("Empty OfferedPsks");
        }
        return this;
    }

    @Override
    public byte[] getBytes() {
        int identitiesSize = identities.stream().mapToInt(id -> 2 + id.identity.length + 4).sum();
        int bindersSize = binders.stream().mapToInt(b -> 1 + b.hmac.length).sum();

        int extensionDataLength = 2 + identitiesSize + 2 + bindersSize;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionDataLength);
        buffer.putShort(TlsConstants.ExtensionType.pre_shared_key.value);
        buffer.putShort((short) extensionDataLength);

        buffer.putShort((short) (identitiesSize));
        for (PskIdentity identity : identities) {
            buffer.putShort((short) identity.identity.length);
            buffer.put(identity.identity);
            buffer.putInt((int) identity.obfuscatedTicketAge);
        }

        binderPosition = buffer.position();
        buffer.putShort((short) bindersSize);
        for (PskBinderEntry binder: binders) {
            buffer.put((byte) binder.hmac.length);
            buffer.put(binder.hmac);
        }

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
    }

    public void calculateBinder(byte[] clientHello, int pskExtensionStartPosition, BinderCalculator calculator) {
        int partialHelloSize = pskExtensionStartPosition + binderPosition;
        byte[] partialHello = new byte[partialHelloSize];
        ByteBuffer.wrap(clientHello).get(partialHello);

        binders.set(0, new PskBinderEntry(calculator.computePskBinder(partialHello)));
    }

    public List<PskIdentity> getIdentities() {
        return identities;
    }

    public List<PskBinderEntry> getBinders() {
        return binders;
    }

    public int getBinderPosition() {
        return binderPosition;
    }

    public static class PskIdentity {
        byte[] identity;
        long obfuscatedTicketAge;

        public PskIdentity(byte[] sessionTicketIdentity, long obfuscatedTicketAge) {
            identity = sessionTicketIdentity;
            this.obfuscatedTicketAge = obfuscatedTicketAge;
        }

        public byte[] getIdentity() {
            return identity;
        }

        public long getObfuscatedTicketAge() {
            return obfuscatedTicketAge;
        }
    }

    public static class PskBinderEntry {
        byte[] hmac;

        public PskBinderEntry(byte[] hmac) {
            this.hmac = hmac;
        }

        public byte[] getHmac() {
            return hmac;
        }
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.pre_shared_key.value;
    }
}
