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
import java.util.Collections;
import java.util.List;

import static tech.kwik.agent15.TlsConstants.decodeSignatureScheme;

/**
 * The TLS signature algorithms extension.
 * See https://tools.ietf.org/html/rfc8446#section-4.2.3
 * "Note: This enum is named "SignatureScheme" because there is already a "SignatureAlgorithm" type in TLS 1.2,
 * which this replaces.  We use the term "signature algorithm" throughout the text."
 */
public class SignatureAlgorithmsExtension extends Extension {

    private List<TlsConstants.SignatureScheme> algorithms = new ArrayList<>();

    public SignatureAlgorithmsExtension() {
        algorithms = Collections.emptyList();
    }

    public SignatureAlgorithmsExtension(List<TlsConstants.SignatureScheme> signatureSchemes) {
        algorithms = signatureSchemes;
    }

    public SignatureAlgorithmsExtension(TlsConstants.SignatureScheme... signatureAlgorithms) {
        this.algorithms = List.of(signatureAlgorithms);
    }

    public SignatureAlgorithmsExtension(ByteBuffer buffer) throws DecodeErrorException {
        int extensionDataLength = parseExtensionHeader(buffer, TlsConstants.ExtensionType.signature_algorithms, 2 + 2);
        int supportedAlgorithmsLength = buffer.getShort() & 0xffff;
        if (extensionDataLength != 2 + supportedAlgorithmsLength) {
            throw new DecodeErrorException("inconsistent length");
        }
        if (supportedAlgorithmsLength % 2 != 0) {
            throw new DecodeErrorException("invalid group length");
        }

        for (int i = 0; i < supportedAlgorithmsLength; i += 2) {
            int supportedAlgorithmBytes = buffer.getShort() & 0xffff;
            decodeSignatureScheme(supportedAlgorithmBytes).ifPresent(algorithm -> algorithms.add(algorithm));
        }
    }

    @Override
    public byte[] getBytes() {
        int extensionLength = 2 + algorithms.size() * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.signature_algorithms.value);
        buffer.putShort((short) extensionLength);  // Extension data length (in bytes)

        buffer.putShort((short) (algorithms.size() * 2));
        for (TlsConstants.SignatureScheme namedGroup: algorithms) {
            buffer.putShort(namedGroup.value);
        }

        return buffer.array();
    }

    public List<TlsConstants.SignatureScheme> getSignatureAlgorithms() {
        return algorithms;
    }

    @Override
    public int getType() {
        return TlsConstants.ExtensionType.signature_algorithms.value;
    }
}
