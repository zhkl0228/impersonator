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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.NewSessionTicket;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.extension.Extension;

import java.util.List;

/**
 * Notifies state changes in the TLS layer.
 */
public interface TlsStatusEventHandler {

    void earlySecretsKnown();

    void handshakeSecretsKnown();

    void handshakeFinished();

    void newSessionTicketReceived(NewSessionTicket ticket);

    void extensionsReceived(List<Extension> extensions) throws TlsProtocolException;

    /**
     * Determines whether early data is accepted by the server. This method is called when the client has indicated
     * it wants to use early data and the TLS layer of the server can accept it; this callback is used to let the
     * server (that uses this library) decide whether it will accept early data.
     * @return
     */
    boolean isEarlyDataAccepted();
}

