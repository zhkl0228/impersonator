/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.ProtectionKeysType;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.handshake.*;

import java.io.IOException;

public interface MessageProcessor {

    default void received(HandshakeMessage msg, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException {
        if (msg instanceof ClientHello) received((ClientHello) msg, protectedBy);
        else if (msg instanceof ServerHello) received((ServerHello) msg, protectedBy);
        else if (msg instanceof EncryptedExtensions) received((EncryptedExtensions) msg, protectedBy);
        else if (msg instanceof CertificateMessage) received((CertificateMessage) msg, protectedBy);
        else if (msg instanceof CertificateVerifyMessage) received((CertificateVerifyMessage) msg, protectedBy);
        else if (msg instanceof FinishedMessage) received((FinishedMessage) msg, protectedBy);
        else if (msg instanceof NewSessionTicketMessage) received((NewSessionTicketMessage) msg, protectedBy);
        else if (msg instanceof CertificateRequestMessage) received((CertificateRequestMessage) msg, protectedBy);
        else throw new TlsProtocolException("Unexpected message type: " + msg.getClass().getSimpleName());
    }

    void received(ClientHello ch, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(ServerHello sh, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(EncryptedExtensions ee, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(CertificateMessage cm, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(CertificateVerifyMessage cv, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(FinishedMessage fm, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(NewSessionTicketMessage nst, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(CertificateRequestMessage cr, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;
}
