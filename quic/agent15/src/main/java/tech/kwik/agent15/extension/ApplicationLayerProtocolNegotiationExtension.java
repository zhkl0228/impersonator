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
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

public class ApplicationLayerProtocolNegotiationExtension extends Extension {

    private final List<String> protocols;

    public ApplicationLayerProtocolNegotiationExtension(String protocol) {
        if (protocol == null || protocol.trim().isEmpty()) {
            throw new IllegalArgumentException("protocol cannot be empty");
        }
        protocols = List.of(protocol);
    }

    public ApplicationLayerProtocolNegotiationExtension(List<String> protocols) {
        if (protocols.isEmpty()) {
            throw new IllegalArgumentException("list of protocols can't be empty");
        }
        if (protocols.stream().anyMatch(s -> s.trim().isEmpty())) {
            throw new IllegalArgumentException("protocol cannot be empty");
        }
        this.protocols = protocols;
    }

    public ApplicationLayerProtocolNegotiationExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.application_layer_protocol_negotiation.value, 3);

        int protocolsLength = buffer.getShort() & 0xffff;
        if (protocolsLength != extensionDataLength - 2) {
            throw new DecodeErrorException("inconsistent lengths");
        }

        protocols = new ArrayList<>();
        while (protocolsLength > 0) {
            int protocolNameLength = buffer.get() & 0xff;
            if (protocolNameLength > protocolsLength - 1) {
                throw new DecodeErrorException("incorrect length");
            }
            byte[] protocolBytes = new byte[protocolNameLength];
            buffer.get(protocolBytes);
            protocols.add(new String(protocolBytes));
            protocolsLength -= (1 + protocolNameLength);
        }
    }

    @Override
    public byte[] getBytes() {
        int protocolNamesLength = protocols.stream().mapToInt(p -> p.getBytes(Charset.forName("UTF-8")).length).sum();
        int size = 4 + 2 + protocols.size() + protocolNamesLength;
        ByteBuffer buffer = ByteBuffer.allocate(size);
        buffer.putShort(TlsConstants.ExtensionType.application_layer_protocol_negotiation.value);
        buffer.putShort((short) (size - 4));
        buffer.putShort((short) (size - 6));
        protocols.forEach(protocol -> {
            byte[] protocolName = protocol.getBytes(Charset.forName("UTF-8"));
            buffer.put((byte) protocolName.length);
            buffer.put(protocolName);
        });

        return buffer.array();
    }

    public List<String> getProtocols() {
        return protocols;
    }

    @Override
    public String toString() {
        return "AlpnExtension " + protocols;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.application_layer_protocol_negotiation.value;
    }
}
