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
package tech.kwik.agent15.handshake;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.log.Logger;

import java.nio.ByteBuffer;

/**
 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.4
 */
public class FinishedMessage extends HandshakeMessage {

    private byte[] verifyData;
    private byte[] raw;

    public FinishedMessage(byte[] hmac) {
        verifyData = hmac;
        serialize();
    }

    public FinishedMessage() {
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.finished;
    }

    public FinishedMessage parse(ByteBuffer buffer, int length) throws DecodeErrorException {
        Logger.debug("Got Finished message (" + length + " bytes)");
        buffer.mark();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.finished, 4 + 32);
        verifyData = new byte[remainingLength];
        buffer.get(verifyData);

        buffer.reset();
        raw = new byte[length];
        buffer.get(raw);

        return this;
    }

    private void serialize() {
        ByteBuffer buffer = ByteBuffer.allocate(4 + verifyData.length);
        buffer.putInt((TlsConstants.HandshakeType.finished.value << 24) | verifyData.length);
        buffer.put(verifyData);
        raw = buffer.array();
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getVerifyData() {
        return verifyData;
    }
}
