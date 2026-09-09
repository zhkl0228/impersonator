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

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.ByteBuffer;

/**
 * TLS Pre-Shared Key Extension, ServerHello variant.
 * see https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
 */
public class ServerPreSharedKeyExtension extends PreSharedKeyExtension {

    private int selectedIdentity;

    public ServerPreSharedKeyExtension(int selectedIdentity) {
        this.selectedIdentity = selectedIdentity;
    }

    public ServerPreSharedKeyExtension() {
    }

    public ServerPreSharedKeyExtension parse(ByteBuffer buffer) throws DecodeErrorException {
        parseExtensionHeader(buffer, TlsConstants.ExtensionType.pre_shared_key, 2);
        selectedIdentity = buffer.getShort();
        return this;
    }

    @Override
    public byte[] getBytes() {
        ByteBuffer buffer = ByteBuffer.allocate(6);
        buffer.putShort(TlsConstants.ExtensionType.pre_shared_key.value);
        buffer.putShort((short) 0x02);
        buffer.putShort((short) selectedIdentity);
        return buffer.array();
    }

    public int getSelectedIdentity() {
        return selectedIdentity;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.pre_shared_key.value;
    }
}
