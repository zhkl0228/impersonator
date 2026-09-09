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
import tech.kwik.agent15.TlsProtocolException;
import tech.kwik.agent15.alert.DecodeErrorException;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

import static tech.kwik.agent15.TlsConstants.decodeSignatureScheme;


/**
 * https://tools.ietf.org/html/rfc8446#section-4.4.3
 * "Certificate Verify
 *   This message is used to provide explicit proof that an endpoint possesses the private key corresponding to its certificate.  The
 *   CertificateVerify message also provides integrity for the handshake up to this point.  Servers MUST send this message when authenticating
 *   via a certificate.  Clients MUST send this message whenever authenticating via a certificate (i.e., when the Certificate message
 *   is non-empty)."
 */
public class CertificateVerifyMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 2 + 2 + 1;
    private TlsConstants.SignatureScheme signatureScheme;
    private byte[] signature;
    private byte[] raw;

    public CertificateVerifyMessage(TlsConstants.SignatureScheme signatureScheme, byte[] signature) {
        this.signatureScheme = signatureScheme;
        this.signature = signature;
        serialize();
    }

    public CertificateVerifyMessage() {
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.certificate_verify;
    }

    public CertificateVerifyMessage parse(ByteBuffer buffer, int length) throws TlsProtocolException {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate_verify, MINIMUM_MESSAGE_SIZE);

        try {
            short signatureSchemeValue = buffer.getShort();
            signatureScheme = decodeSignatureScheme(signatureSchemeValue).orElse(null);

            int signatureLength = buffer.getShort() & 0xffff;
            signature = new byte[signatureLength];
            buffer.get(signature);
            if (buffer.position() - startPosition != 4 + remainingLength) {
                throw new DecodeErrorException("Incorrect message length");
            }

            raw = new byte[length];
            buffer.position(startPosition);
            buffer.get(raw);

            return this;
        }
        catch (BufferUnderflowException notEnoughBytes) {
            throw new DecodeErrorException("message underflow");
        }
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    private void serialize() {
        int signatureLength = signature.length;
        ByteBuffer buffer = ByteBuffer.allocate(4 + 2 + 2 + signatureLength);
        buffer.putInt((TlsConstants.HandshakeType.certificate_verify.value << 24) | (2 + 2 + signatureLength));
        buffer.putShort(signatureScheme.value);
        buffer.putShort((short) signatureLength);
        buffer.put(signature);
        raw = buffer.array();
    }

    /**
     * @return  the signature scheme or null if the message contained an unknown signature scheme value
     */
    public TlsConstants.SignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public byte[] getSignature() {
        return signature;
    }
}
