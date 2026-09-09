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
package tech.kwik.agent15.engine.impl;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.handshake.HandshakeMessage;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

// https://tools.ietf.org/html/rfc8446#section-4.4.1
// "Many of the cryptographic computations in TLS make use of a transcript hash. This value is computed by hashing the
//  concatenation of each included handshake message, including the handshake message header carrying the handshake
//  message type and length fields, but not including record layer headers."
public class TranscriptHash {

    enum ExtendedHandshakeType {
        client_hello(1),
        server_hello(2),
        new_session_ticket(4),
        end_of_early_data(5),
        encrypted_extensions(8),
        certificate(11),
        certificate_request(13),
        certificate_verify(15),
        finished(20),
        key_update(24),
        server_certificate(249),
        server_certificate_verify(250),
        server_finished(251),
        client_certificate(252),
        client_certificate_verify(253),
        client_finished(254)
        ;

        public final byte value;

        ExtendedHandshakeType(int value) {
            this.value = (byte) value;
        }
    }

    // https://tools.ietf.org/html/rfc8446#section-4.4.1
    // "For concreteness, the transcript hash is always taken from the
    //   following sequence of handshake messages, starting at the first
    //   ClientHello and including only those messages that were sent:
    //   ClientHello, HelloRetryRequest, ClientHello, ServerHello,
    //   EncryptedExtensions, server CertificateRequest, server Certificate,
    //   server CertificateVerify, server Finished, EndOfEarlyData, client
    //   Certificate, client CertificateVerify, client Finished."
    private static ExtendedHandshakeType[] hashedMessages = {
            ExtendedHandshakeType.client_hello,
            ExtendedHandshakeType.server_hello,
            ExtendedHandshakeType.encrypted_extensions,
            ExtendedHandshakeType.certificate_request,
            ExtendedHandshakeType.server_certificate,
            ExtendedHandshakeType.server_certificate_verify,
            ExtendedHandshakeType.server_finished,
            ExtendedHandshakeType.client_certificate,
            ExtendedHandshakeType.client_certificate_verify,
            ExtendedHandshakeType.client_finished
    };

    private final MessageDigest hashFunction;

    private Map<ExtendedHandshakeType, byte[]> msgData = new ConcurrentHashMap<>();
    private Map<ExtendedHandshakeType, byte[]> hashes = new ConcurrentHashMap<>();


    public TranscriptHash(int hashLength) {
        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        String hashAlgorithm = "SHA-" + (hashLength * 8);
        try {
            hashFunction = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + hashAlgorithm + " support");
        }
    }

    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated message type.
     * @param msgType
     * @return
     */
    public byte[] getHash(TlsConstants.HandshakeType msgType) {
        return getHash(convert(msgType));
    }

    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated client message type.
     * For example, when the <code>msgType</code> parameter has value <code>certificate</code>, the transcript hash for
     * the concatenation of handshake messages up to (and including) the client certificate message is returned.
     * @param msgType
     * @return
     */
    public byte[] getClientHash(TlsConstants.HandshakeType msgType) {
        return getHash(convert(msgType, true));
    }

    /**
     * Return the transcript hash for the messages in the handshake up to and including the indicated server message type.
     * For example, when the <code>msgType</code> parameter has value <code>certificate</code>, the transcript hash for
     * the concatenation of handshake messages up to (and including) the server certificate message is returned.
     * @param msgType
     * @return
     */
    public byte[] getServerHash(TlsConstants.HandshakeType msgType) {
        return getHash(convert(msgType, false));
    }

    /**
     * Record a handshake message for computing the transcript hash. The type of the message determines its position
     * in the transcript hash computation.
     * @param msg
     */
    public void record(HandshakeMessage msg) {
        List<TlsConstants.HandshakeType> ambigousTypes = List.of(TlsConstants.HandshakeType.certificate,
                TlsConstants.HandshakeType.certificate_verify, TlsConstants.HandshakeType.finished);
        if (ambigousTypes.contains(msg.getType())) {
            throw new IllegalArgumentException();
        }
        msgData.put(convert(msg.getType()), msg.getBytes());
    }

    /**
     * Record a client handshake message for computing the transcript hash. This method is needed because the
     * <code>TlsConstants.HandshakeType</code> type does not differentiate between client and server variants, whilst
     * these variants have a different position in the transcript hash computation.
     * Note that the term "client" here refers to the message type, not whether it is sent or received by a client.
     * For example, a client certificate message is sent by the client and received by the server; both need to use
     * this method to record the message.
     * @param msg
     */
    public void recordClient(HandshakeMessage msg) {
        msgData.put(convert(msg.getType(), true), msg.getBytes());
    }

    /**
     * Record a server handshake message for computing the transcript hash. This method is needed because the
     * <code>TlsConstants.HandshakeType</code> type does not differentiate between client and server variants, whilst
     * these variants have a different position in the transcript hash computation.
     * Note that the term "server" here refers to the message type, not whether it is sent or received by a server.
     * For example, a server certificate message is sent by the server and received by the client; both need to use
     * this method to record the message.
     * @param msg
     */
    public void recordServer(HandshakeMessage msg) {
        msgData.put(convert(msg.getType(), false), msg.getBytes());
    }

    private byte[] getHash(ExtendedHandshakeType type) {
        if (! hashes.containsKey(type)) {
            computeHash(type);
        }
        return hashes.get(type);
    }

   private void computeHash(ExtendedHandshakeType requestedType) {
        for (ExtendedHandshakeType type: hashedMessages) {
            if (msgData.containsKey(type)) {
                hashFunction.update(msgData.get(type));
            }
            if (type == requestedType) {
                break;
            }
        }
        hashes.put(requestedType, hashFunction.digest());
    }

    private ExtendedHandshakeType convert(TlsConstants.HandshakeType type) {
        List<TlsConstants.HandshakeType> ambigousTypes = List.of(TlsConstants.HandshakeType.certificate,
                TlsConstants.HandshakeType.certificate_verify, TlsConstants.HandshakeType.finished);
        if (ambigousTypes.contains(type)) {
            throw new IllegalArgumentException("cannot convert ambiguous type " + type);
        }
        return ExtendedHandshakeType.values()[type.ordinal()];
    }

    private ExtendedHandshakeType convert(TlsConstants.HandshakeType type, boolean client) {
        if (type == TlsConstants.HandshakeType.finished) {
            return client? ExtendedHandshakeType.client_finished: ExtendedHandshakeType.server_finished;
        }
        else if (type == TlsConstants.HandshakeType.certificate) {
            return client? ExtendedHandshakeType.client_certificate: ExtendedHandshakeType.server_certificate;
        }
        else if (type == TlsConstants.HandshakeType.certificate_verify) {
            return client? ExtendedHandshakeType.client_certificate_verify: ExtendedHandshakeType.server_certificate_verify;
        }
        return ExtendedHandshakeType.values()[type.ordinal()];
    }
}
