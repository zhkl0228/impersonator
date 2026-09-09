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
import java.util.ArrayList;
import java.util.List;

import static tech.kwik.agent15.TlsConstants.decodeNamedGroup;

/**
 * The TLS supported groups extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.7
 */
public class SupportedGroupsExtension extends Extension {

    private final List<TlsConstants.NamedGroup> namedGroups = new ArrayList<>();

    public SupportedGroupsExtension(TlsConstants.NamedGroup namedGroup) {
        namedGroups.add(namedGroup);
    }

    public SupportedGroupsExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.supported_groups, 2 + 2);
        int namedGroupsLength = buffer.getShort() & 0xffff;
        if (extensionDataLength != 2 + namedGroupsLength) {
            throw new DecodeErrorException("inconsistent length");
        }
        if (namedGroupsLength % 2 != 0) {
            throw new DecodeErrorException("invalid group length");
        }

        for (int i = 0; i < namedGroupsLength; i += 2) {
            int namedGroupBytes = buffer.getShort() & 0xffff;
            decodeNamedGroup(namedGroupBytes).ifPresent(algorithm -> namedGroups.add(algorithm));
        }
    }

    @Override
    public byte[] getBytes() {
        int extensionLength = 2 + namedGroups.size() * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.supported_groups.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (namedGroups.size() * 2));
        for (TlsConstants.NamedGroup namedGroup: namedGroups) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }

    @Override
    public String toString() {
        return "SupportedGroupsExtension" + namedGroups;
    }

    public List<TlsConstants.NamedGroup> getNamedGroups() {
        return namedGroups;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.supported_groups.value;
    }
}
