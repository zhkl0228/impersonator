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
package tech.kwik.agent15;

import tech.kwik.agent15.handshake.NewSessionTicketMessage;

import java.nio.ByteBuffer;
import java.util.Date;
import java.util.stream.Stream;


public class NewSessionTicket {

    protected byte[] psk;
    protected Date ticketCreationDate;
    protected long ticketAgeAdd;
    protected byte[] ticket;
    protected int ticketLifeTime;
    protected boolean hasEarlyDataExtension;
    protected long earlyDataMaxSize;
    protected TlsConstants.CipherSuite cipher;

    protected NewSessionTicket() {
    }

    public NewSessionTicket(byte[] psk, NewSessionTicketMessage newSessionTicketMessage, TlsConstants.CipherSuite currentCipher) {
        this.psk = psk;
        ticketCreationDate = new Date();
        ticketAgeAdd = newSessionTicketMessage.getTicketAgeAdd();
        ticket = newSessionTicketMessage.getTicket();
        ticketLifeTime = newSessionTicketMessage.getTicketLifetime();
        cipher = currentCipher;
        hasEarlyDataExtension = newSessionTicketMessage.getEarlyDataExtension() != null;
        if (hasEarlyDataExtension) {
            earlyDataMaxSize = newSessionTicketMessage.getEarlyDataExtension().getMaxEarlyDataSize();
        }
    }

    protected NewSessionTicket(byte[] data) {
        ByteBuffer buffer = ByteBuffer.wrap(data);
        ticketCreationDate = new Date(buffer.getLong());
        ticketAgeAdd = buffer.getLong();
        int ticketSize = buffer.getInt();
        ticket = new byte[ticketSize];
        buffer.get(ticket);
        int pskSize = buffer.getInt();
        psk = new byte[pskSize];
        buffer.get(psk);
        if (buffer.remaining() > 0) {
            ticketLifeTime = buffer.getInt();
        }
        if (buffer.remaining() > 0) {
            short cipherEncoding = buffer.getShort();
            cipher = Stream.of(TlsConstants.CipherSuite.values()).filter(c -> c.value == cipherEncoding).findAny().orElseThrow();
        }
        else {
            cipher = TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256;
        }
        if (buffer.remaining() > 0) {
            hasEarlyDataExtension = true;
            earlyDataMaxSize = buffer.getLong();
        }
    }

    public static NewSessionTicket deserialize(byte[] data) {
        return new NewSessionTicket(data);
    }

    public byte[] serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(1000);
        buffer.putLong(ticketCreationDate.getTime());
        buffer.putLong(ticketAgeAdd);
        buffer.putInt(ticket.length);
        buffer.put(ticket);
        buffer.putInt(psk.length);
        buffer.put(psk);
        buffer.putInt(ticketLifeTime);
        buffer.putShort(cipher.value);
        if (hasEarlyDataExtension) {
            buffer.putLong(earlyDataMaxSize);
        }
        else {
            buffer.putLong(0L);
        }

        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);

        return data;
    }

    int validFor() {
        return Integer.max(0, (int) ((ticketCreationDate.getTime() + ticketLifeTime * 1000) - new Date().getTime()) / 1000);
    }

    public byte[] getPSK() {
        return psk;
    }

    public Date getTicketCreationDate() {
        return ticketCreationDate;
    }

    public long getTicketAgeAdd() {
        return ticketAgeAdd;
    }

    public byte[] getSessionTicketIdentity() {
        return ticket;
    }
    
    public byte[] getTicket() {
        return ticket;
    }

    public int getTicketLifeTime() {
        return ticketLifeTime;
    }

    public TlsConstants.CipherSuite getCipher() {
        return cipher;
    }

    public boolean hasEarlyDataExtension() {
        return hasEarlyDataExtension;
    }

    public long getEarlyDataMaxSize() {
        return earlyDataMaxSize;
    }

    @Override
    public String toString() {
        return "Ticket, creation date = " + ticketCreationDate + ", ticket lifetime = " + ticketLifeTime
                + (validFor() > 0 ? " (still valid for " + validFor() + " seconds)": " (not valid anymore)");
    }
}
