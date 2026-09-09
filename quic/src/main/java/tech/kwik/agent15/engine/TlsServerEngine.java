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
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.FinishedMessage;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.function.Function;

public interface TlsServerEngine extends TlsEngine {

    /**
     * Adds ciphers to the list of the symmetric cipher options supported by the server
     * (specifically the record protection algorithm (including secret key length) and a hash to be used with HKDF),
     * in descending order of server preference.
     * By default, the server supports TLS_AES_128_GCM_SHA256.
     * @param cipherSuites
     */
    void addSupportedCiphers(List<TlsConstants.CipherSuite> cipherSuites);

    /**
     * Sets the negotiated application layer protocol.
     * @param applicationProtocol
     */
    void setSelectedApplicationLayerProtocol(String applicationProtocol);

    /**
     * Adds extension to the list of extensions to be included in the EncryptedExtensions message.
     * @param extension
     */
    void addServerExtensions(Extension extension);

    /**
     * Sets the callback used for sending server messages (to the client).
     * @param serverMessageSender
     */
    void setServerMessageSender(ServerMessageSender serverMessageSender);

    /**
     * Sets the callback used for notifying the status of the TLS connection.
     * @param statusHandler
     */
    void setStatusHandler(TlsStatusEventHandler statusHandler);

    /**
     * Set the callback that is called before a session is (successfully) resumed. If there is no data associated with
     * the session, the callback is not called and verification is assumed to be successful, i.e. the session will be
     * resumed.
     * @param callback  the callback that is called with the stored session data; when the callback returns false
     *                  the session will not be resumed.
     */
    void setSessionDataVerificationCallback(Function<ByteBuffer, Boolean> callback);

    /**
     * Get the selected (negotiated) cipher suite.
     * @return
     */
    TlsConstants.CipherSuite getSelectedCipher();

    /**
     * Returns the list of extensions actually included in the EncryptedExtensions message.
     * @return
     */
    List<Extension> getServerExtensions();

    /**
     * Set (other layer's) session data for this session. When this session is resumed (with a session ticket),
     * this data will be provided to the session data verification callback, which enables the application layer to
     * accept or deny the session resumption based on the data stored in the session.
     * For example, with QUIC this is used to store the QUIC version in the session data, so when the session is
     * resumed, the QUIC layer can verify the same QUIC version is used.
     * @param additionalSessionData
     */
    void setSessionData(byte[] additionalSessionData);

    void received(ClientHello clientHello, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;

    void received(FinishedMessage clientFinished, ProtectionKeysType protectedBy) throws TlsProtocolException, IOException;
}