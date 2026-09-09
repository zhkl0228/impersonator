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
package tech.kwik.agent15.engine.impl;

import at.favre.lib.hkdf.HKDF;
import at.favre.lib.hkdf.HkdfMacFactory;
import tech.kwik.agent15.BinderCalculator;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.alert.IllegalParameterAlert;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.XECPublicKey;




public class TlsState implements BinderCalculator {

    private static final Charset ISO_8859_1 = Charset.forName("ISO-8859-1");

    private static String labelPrefix = "tls13 ";

    private final MessageDigest hashFunction;
    private final HKDF hkdf;
    private final byte[] emptyHash;
    private final short keyLength;
    private final short hashLength;
    private final short iv_length = 12;
    private boolean pskSelected;
    private PublicKey serverSharedKey;
    private PrivateKey clientPrivateKey;
    private final byte[] psk;
    private byte[] earlySecret;
    private byte[] binderKey;
    private byte[] resumptionMasterSecret;
    private byte[] serverHandshakeTrafficSecret;
    private byte[] clientEarlyTrafficSecret;
    private byte[] clientHandshakeTrafficSecret;
    private byte[] handshakeSecret;
    private byte[] clientApplicationTrafficSecret;
    private byte[] serverApplicationTrafficSecret;
    private final TranscriptHash transcriptHash;
    private byte[] sharedSecret;
    private byte[] masterSecret;

    public TlsState(TranscriptHash transcriptHash, byte[] psk, int keyLength, int hashLength) {
        this.psk = psk;
        this.transcriptHash = transcriptHash;
        this.keyLength = (short) keyLength;
        this.hashLength = (short) hashLength;

        // https://tools.ietf.org/html/rfc8446#section-7.1
        // "The Hash function used by Transcript-Hash and HKDF is the cipher suite hash algorithm."
        String hashAlgorithm = "SHA-" + (this.hashLength * 8);
        try {
            hashFunction = MessageDigest.getInstance(hashAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + hashAlgorithm + " support");
        }
        String macAlgorithm = "HmacSHA" + (this.hashLength * 8);
        hkdf = HKDF.from(new HkdfMacFactory.Default(macAlgorithm, null));

        emptyHash = hashFunction.digest(new byte[0]);

        if (psk == null) {
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "If a given secret is not available, then the 0-value consisting of a
            //   string of Hash.length bytes set to zeros is used."
            psk = new byte[this.hashLength];
        }
        computeEarlySecret(psk);
    }

    public TlsState(TranscriptHash transcriptHash, int keyLength, int hashLength) {
        this(transcriptHash, null, keyLength, hashLength);
    }

    private byte[] computeEarlySecret(byte[] ikm) {
        byte[] zeroSalt = new byte[hashLength];
        earlySecret = hkdf.extract(zeroSalt, ikm);

        binderKey = hkdfExpandLabel(earlySecret, "res binder", emptyHash, hashLength);

        return earlySecret;
    }

    @Override
    public byte[] computePskBinder(byte[] partialClientHello) {
        String macAlgorithmName = "HmacSHA" + (hashLength * 8);
        try {
            hashFunction.reset();
            hashFunction.update(partialClientHello);
            byte[] hash = hashFunction.digest();

            byte[] finishedKey = hkdfExpandLabel(binderKey, "finished", "", hashLength);
            SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, macAlgorithmName);

            Mac hmacAlgorithm = Mac.getInstance(macAlgorithmName);
            hmacAlgorithm.init(hmacKey);
            hmacAlgorithm.update(hash);
            byte[] hmac = hmacAlgorithm.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + macAlgorithmName + " support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    public void computeSharedSecret() throws IllegalParameterAlert {
        try {
            KeyAgreement keyAgreement;
            if (serverSharedKey instanceof ECPublicKey) {
                keyAgreement = KeyAgreement.getInstance("ECDH");
            }
            else if (serverSharedKey instanceof XECPublicKey) {
                keyAgreement = KeyAgreement.getInstance("XDH");
            }
            else {
                throw new RuntimeException("Unsupported key type");
            }

            keyAgreement.init(clientPrivateKey);
            keyAgreement.doPhase(serverSharedKey, true);

            sharedSecret = keyAgreement.generateSecret();
        }
        catch (InvalidKeyException e) {
            // This can be caused by an invalid public key, e.g. a low-order point for X25519.
            throw new IllegalParameterAlert("invalid public key: " + e.getMessage());
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unsupported crypto: " + e);
        }
    }

    public void computeEarlyTrafficSecret() {
        byte[] clientHelloHash = transcriptHash.getHash(TlsConstants.HandshakeType.client_hello);

        clientEarlyTrafficSecret = hkdfExpandLabel(earlySecret, "c e traffic", clientHelloHash, hashLength);
    }

    public void computeHandshakeSecrets() {
        byte[] derivedSecret = hkdfExpandLabel(earlySecret, "derived", emptyHash, hashLength);

        handshakeSecret = hkdf.extract(derivedSecret, sharedSecret);

        byte[] handshakeHash = transcriptHash.getHash(TlsConstants.HandshakeType.server_hello);

        clientHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "c hs traffic", handshakeHash, hashLength);

        serverHandshakeTrafficSecret = hkdfExpandLabel(handshakeSecret, "s hs traffic", handshakeHash, hashLength);

        /*
        The following secrets are not needed for QUIC, as QUIC derives keys directly from the traffic secrets.
        They would be needed for TLS over TCP, but as this library is focused on QUIC, there is no need to compute them.

        byte[] clientHandshakeKey = hkdfExpandLabel(clientHandshakeTrafficSecret, "key", "", keyLength);

        byte[] serverHandshakeKey = hkdfExpandLabel(serverHandshakeTrafficSecret, "key", "", keyLength);

        byte[] clientHandshakeIV = hkdfExpandLabel(clientHandshakeTrafficSecret, "iv", "", iv_length);

        byte[] serverHandshakeIV = hkdfExpandLabel(serverHandshakeTrafficSecret, "iv", "", iv_length);
         */
    }

    public void computeApplicationSecrets() {
        computeApplicationSecrets(handshakeSecret);
    }

    void computeApplicationSecrets(byte[] handshakeSecret) {
        byte[] serverFinishedHash = transcriptHash.getServerHash(TlsConstants.HandshakeType.finished);

        byte[] derivedSecret = hkdfExpandLabel(handshakeSecret, "derived", emptyHash, hashLength);

        byte[] zeroKey = new byte[hashLength];
        masterSecret = hkdf.extract(derivedSecret, zeroKey);

        clientApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "c ap traffic", serverFinishedHash, hashLength);

        serverApplicationTrafficSecret = hkdfExpandLabel(masterSecret, "s ap traffic", serverFinishedHash, hashLength);

        /*
        The following secrets are not needed for QUIC, as QUIC derives keys directly from the traffic secrets.
        They would be needed for TLS over TCP, but as this library is focused on QUIC, there is no need to compute them.

        byte[] clientApplicationKey = hkdfExpandLabel(clientApplicationTrafficSecret, "key", "", keyLength);

        byte[] serverApplicationKey = hkdfExpandLabel(serverApplicationTrafficSecret, "key", "", keyLength);

        byte[] clientApplicationIv = hkdfExpandLabel(clientApplicationTrafficSecret, "iv", "", iv_length);

        byte[] serverApplicationIv = hkdfExpandLabel(serverApplicationTrafficSecret, "iv", "", iv_length);
        */
    }

    public void computeResumptionMasterSecret() {
        byte[] clientFinishedHash = transcriptHash.getClientHash(TlsConstants.HandshakeType.finished);

        resumptionMasterSecret = hkdfExpandLabel(masterSecret, "res master", clientFinishedHash, hashLength);
    }

    // https://tools.ietf.org/html/rfc8446#section-4.6.1
    // "The PSK associated with the ticket is computed as:
    //       HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)"
    public byte[] computePSK(byte[] ticketNonce) {
        byte[] psk = hkdfExpandLabel(resumptionMasterSecret, "resumption", ticketNonce, hashLength);
        return psk;
    }

    public byte[] hkdfExpandLabel(byte[] secret, String label, String context, short length) {
        return hkdfExpandLabel(secret, label, context.getBytes(ISO_8859_1), length);
    }

    byte[] hkdfExpandLabel(byte[] secret, String label, byte[] context, short length) {
        // See https://tools.ietf.org/html/rfc8446#section-7.1 for definition of HKDF-Expand-Label.
        ByteBuffer hkdfLabel = ByteBuffer.allocate(2 + 1 + labelPrefix.length() + label.getBytes(ISO_8859_1).length + 1 + context.length);
        hkdfLabel.putShort(length);
        hkdfLabel.put((byte) (labelPrefix.length() + label.getBytes().length));
        hkdfLabel.put(labelPrefix.getBytes(ISO_8859_1));
        hkdfLabel.put(label.getBytes(ISO_8859_1));
        hkdfLabel.put((byte) (context.length));
        hkdfLabel.put(context);
        return hkdf.expand(secret, hkdfLabel.array(), length);
    }

    public short getHashLength() {
        return hashLength;
    }

    public byte[] getClientEarlyTrafficSecret() {
        return clientEarlyTrafficSecret;
    }

    public byte[] getClientHandshakeTrafficSecret() {
        return clientHandshakeTrafficSecret;
    }

    public byte[] getServerHandshakeTrafficSecret() {
        return serverHandshakeTrafficSecret;
    }

    public byte[] getClientApplicationTrafficSecret() {
        return clientApplicationTrafficSecret;
    }

    public byte[] getServerApplicationTrafficSecret() {
        return serverApplicationTrafficSecret;
    }

    public void setOwnKey(PrivateKey clientPrivateKey) {
        this.clientPrivateKey = clientPrivateKey;
    }

    public void setPskSelected(int selectedIdentity) throws IllegalParameterAlert {
        pskSelected = true;
    }

    public void setNoPskSelected() {
        if (psk != null && !pskSelected) {
            // Recompute early secret, as psk is not accepted by server.
            // https://tools.ietf.org/html/rfc8446#section-7.1
            // "... if no PSK is selected, it will then need to compute the Early Secret corresponding to the zero PSK."
            computeEarlySecret(new byte[hashLength]);
        }
    }

    public void setPeerKey(PublicKey serverSharedKey) {
        this.serverSharedKey = serverSharedKey;
    }
}
