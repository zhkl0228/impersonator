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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.impl.TlsState;
import tech.kwik.agent15.extension.ClientHelloPreSharedKeyExtension;
import tech.kwik.agent15.handshake.NewSessionTicketMessage;

import java.util.List;

public interface TlsSessionRegistry {

    NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite selectedCipher, TlsState tlsState,
                                                          String selectedApplicationLayerProtocol);

    NewSessionTicketMessage createNewSessionTicketMessage(byte ticketNonce, TlsConstants.CipherSuite selectedCipher, TlsState tlsState,
                                                          String selectedApplicationLayerProtocol, Long maxEarlyDataSize, byte[] data);

    Integer selectIdentity(List<ClientHelloPreSharedKeyExtension.PskIdentity> identities, TlsConstants.CipherSuite selectedCipher);

    TlsSession useSession(ClientHelloPreSharedKeyExtension.PskIdentity pskIdentity);

    /**
     * Returns the session data for the given PSK identity.
     * @param pskIdentity
     * @return  the session data for the given PSK identity, or null if no session data was registered for the given PSK identity
     */
    byte[] peekSessionData(ClientHelloPreSharedKeyExtension.PskIdentity pskIdentity);

    void shutdown();
}
