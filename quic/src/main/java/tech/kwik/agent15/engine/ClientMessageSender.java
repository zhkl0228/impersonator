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

import tech.kwik.agent15.handshake.CertificateMessage;
import tech.kwik.agent15.handshake.CertificateVerifyMessage;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.FinishedMessage;

import java.io.IOException;


public interface ClientMessageSender {

    void send(ClientHello clientHello) throws IOException;

    void send(FinishedMessage finishedMessage) throws IOException;

    void send(CertificateMessage certificateMessage) throws IOException;

    void send(CertificateVerifyMessage certificateVerifyMessage);
}
