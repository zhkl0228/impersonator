/*
 * Copyright © 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
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

import tech.kwik.agent15.alert.BadCertificateAlert;
import tech.kwik.agent15.alert.DecodeErrorException;
import tech.kwik.agent15.TlsConstants;

import java.io.ByteArrayInputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

// https://tools.ietf.org/html/rfc8446#section-4.4.2
public class CertificateMessage extends HandshakeMessage {

    private static final int MINIMUM_MESSAGE_SIZE = 1 + 3 + 1 + 3 + 3 + 2;
    private byte[] requestContext;
    private X509Certificate endEntityCertificate;
    private List<X509Certificate> certificateChain = new ArrayList<>();
    private byte[] raw;

    public CertificateMessage(X509Certificate certificate) {
        this.requestContext = new byte[0];
        endEntityCertificate = certificate;
        if (certificate != null) {
            certificateChain = List.of(certificate);
        }
        else {
            certificateChain = Collections.emptyList();
        }

        serialize();
    }

    /**
     * @param certificateChain     The server certificate must be the first in the list
     */
    public CertificateMessage(List<X509Certificate> certificateChain) {
        Objects.requireNonNull(certificateChain);
        if (certificateChain.size() < 1) {
            throw new IllegalArgumentException();
        }
        this.requestContext = new byte[0];
        endEntityCertificate = certificateChain.get(0);
        this.certificateChain = certificateChain;

        serialize();
    }

    public CertificateMessage(byte[] requestContext, X509Certificate certificate) {
        Objects.requireNonNull(certificate);
        this.requestContext = requestContext;
        endEntityCertificate = certificate;
        certificateChain = List.of(certificate);

        serialize();
    }

    public CertificateMessage() {
    }

    @Override
    public TlsConstants.HandshakeType getType() {
        return TlsConstants.HandshakeType.certificate;
    }

    public CertificateMessage parse(ByteBuffer buffer) throws DecodeErrorException, BadCertificateAlert {
        int startPosition = buffer.position();
        int remainingLength = parseHandshakeHeader(buffer, TlsConstants.HandshakeType.certificate, MINIMUM_MESSAGE_SIZE);

        try {
            int certificateRequestContextSize = buffer.get() & 0xff;
            if (certificateRequestContextSize > 0) {
                requestContext = new byte[certificateRequestContextSize];
                buffer.get(requestContext);
            }
            else {
                requestContext = new byte[0];
            }
            parseCertificateEntries(buffer);

            // Update state.
            raw = new byte[4 + remainingLength];
            buffer.position(startPosition);
            buffer.get(raw);

            return this;
        }
        catch (BufferUnderflowException notEnoughBytes) {
            throw new DecodeErrorException("message underflow");
        }
    }

    private int parseCertificateEntries(ByteBuffer buffer) throws BadCertificateAlert {
        int certificateListSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
        int remainingCertificateBytes = certificateListSize;
        int certCount = 0;

        while (remainingCertificateBytes > 0) {
            int certSize = ((buffer.get() & 0xff) << 16) | ((buffer.get() & 0xff) << 8) | (buffer.get() & 0xff);
            byte[] certificateData = new byte[certSize];
            buffer.get(certificateData);

            if (certSize > 0) {
                // https://tools.ietf.org/html/rfc8446#section-4.4.2
                // "If the corresponding certificate type extension ("server_certificate_type" or "client_certificate_type")
                // was not negotiated in EncryptedExtensions, or the X.509 certificate type was negotiated, then each
                // CertificateEntry contains a DER-encoded X.509 certificate."
                // This implementation does not support raw-public-key certificates, so the only type supported is X509.
                try {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateData));
                    if (certCount == 0) {
                        // https://tools.ietf.org/html/rfc8446#section-4.4.2
                        // "The sender's certificate MUST come in the first CertificateEntry in the list. "
                        endEntityCertificate = certificate;
                    }
                    certificateChain.add(certificate);
                } catch (CertificateException e) {
                    throw new BadCertificateAlert("could not parse certificate");
                }
            }

            remainingCertificateBytes -= (3 + certSize);
            certCount++;
            int extensionsSize = buffer.getShort() & 0xffff;
            // https://tools.ietf.org/html/rfc8446#section-4.4.2
            // "Valid extensions for server certificates at present include the OCSP Status extension [RFC6066]
            // and the SignedCertificateTimestamp extension [RFC6962];..."
            // None of them is (yet) supported by this implementation.
            byte[] extensionData = new byte[extensionsSize];
            buffer.get(extensionData);
            remainingCertificateBytes -= (2 + extensionsSize);
        }
        return certCount;
    }

    private void serialize() {
        int nrOfCerts = certificateChain.size();
        List<byte[]> encodedCerts = certificateChain.stream()
                .map(cert -> encode(cert))
                .collect(Collectors.toList());

        int msgSize = 4 + 1 + 3 + nrOfCerts * (3 + 2) + encodedCerts.stream().mapToInt(bytes -> bytes.length).sum();
        ByteBuffer buffer = ByteBuffer.allocate(msgSize);

        buffer.putInt((TlsConstants.HandshakeType.certificate.value << 24) | (msgSize - 4));
        // cert request context size
        buffer.put((byte) 0x00);
        // certificate_list size (3 bytes)
        buffer.put((byte) 0); // assuming < 65535
        buffer.putShort((short) (msgSize - 4 - 1 - 3));

        encodedCerts.forEach(encodedCert -> {
            if (encodedCert.length > 0xfff0) {
                throw new RuntimeException("Certificate size not supported");
            }
            // certificate size
            buffer.put((byte) 0);
            buffer.putShort((short) encodedCert.length);
            // certificate
            buffer.put(encodedCert);
            // extensions size
            buffer.putShort((short) 0);
        });
        raw = buffer.array();
    }

    byte[] encode(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            // Impossible with valid certificate
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] getBytes() {
        return raw;
    }

    public byte[] getRequestContext() {
        return requestContext;
    }

    public X509Certificate getEndEntityCertificate() {
        return endEntityCertificate;
    }

    public List<X509Certificate> getCertificateChain() {
        return certificateChain;
    }
}
