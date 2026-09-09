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
import tech.kwik.agent15.alert.ErrorAlert;
import tech.kwik.agent15.alert.HandshakeFailureAlert;
import tech.kwik.agent15.alert.InternalErrorAlert;
import tech.kwik.agent15.engine.TlsEngine;
import tech.kwik.agent15.env.AlgorithmMapping;
import tech.kwik.agent15.env.PlatformMapping;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.UnknownExtension;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PSSParameterSpec;

import static tech.kwik.agent15.TlsConstants.NamedGroup.*;
import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;

public abstract class TlsEngineImpl implements TlsEngine {

    protected PublicKey publicKey;
    protected PrivateKey privateKey;
    protected TlsState state;
    protected AlgorithmMapping algorithmMapping;

    public TlsEngineImpl() {
        algorithmMapping = PlatformMapping.algorithmMapping();
    }

    public abstract TlsConstants.CipherSuite getSelectedCipher();

    public static int hashLength(TlsConstants.CipherSuite cipher) {
        switch (cipher) {
            case TLS_AES_128_GCM_SHA256:
                return 256 / 8;
            case TLS_AES_256_GCM_SHA384:
                return 384 / 8;
            case TLS_CHACHA20_POLY1305_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_8_SHA256:
                return 256 / 8;
            default:
                // Impossible, as all enum values are covered
                throw new RuntimeException();
        }
    }

    public static int keyLength(TlsConstants.CipherSuite cipher) {
        switch (cipher) {
            case TLS_AES_128_GCM_SHA256:
                return 128 / 8;
            case TLS_AES_256_GCM_SHA384:
                return 256 / 8;
            case TLS_CHACHA20_POLY1305_SHA256:
                return 256 / 8;
            case TLS_AES_128_CCM_SHA256:
                return 128 / 8;
            case TLS_AES_128_CCM_8_SHA256:
                return 128 / 8;
            default:
                // Impossible, as all enum values are covered
                throw new RuntimeException();
        }
    }

    protected void generateKeys(TlsConstants.NamedGroup namedGroup) {
        try {
            KeyPairGenerator keyPairGenerator;
            if (namedGroup == secp256r1 || namedGroup == secp384r1 || namedGroup == secp521r1) {
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(new ECGenParameterSpec(namedGroup.toString()));
            }
            else if (namedGroup == x25519 || namedGroup == x448) {
                keyPairGenerator = KeyPairGenerator.getInstance("XDH");
                NamedParameterSpec paramSpec = new NamedParameterSpec(namedGroup.toString().toUpperCase());  // x25519 => X25519
                keyPairGenerator.initialize(paramSpec);
            }
            else {
                throw new RuntimeException("unsupported group " + namedGroup);
            }

            KeyPair keyPair = keyPairGenerator.genKeyPair();
            privateKey = keyPair.getPrivate();
            publicKey = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            // Invalid runtime
            throw new RuntimeException("missing key pair generator algorithm EC");
        } catch (InvalidAlgorithmParameterException e) {
            // Impossible, would be programming error
            throw new RuntimeException();
        }
    }

    /**
     * Compute the signature used in certificate verify message to proof possession of private key.
     * @param content  the content to be signed (transcript hash)
     * @param certificatePrivateKey  the private key associated with the certificate
     * @param signatureScheme
     * @param client  whether the signature must be computed
     * @return
     */
    protected byte[] computeSignature(byte[] content, PrivateKey certificatePrivateKey, TlsConstants.SignatureScheme signatureScheme, boolean client) throws ErrorAlert {
        // https://tools.ietf.org/html/rfc8446#section-4.4.3

        //   The digital signature is then computed over the concatenation of:
        //   -  A string that consists of octet 32 (0x20) repeated 64 times
        //   -  The context string
        //   -  A single 0 byte which serves as the separator
        //   -  The content to be signed"
        ByteArrayOutputStream signatureInput = new ByteArrayOutputStream();
        try {
            signatureInput.write(new String(new byte[] { 0x20 }).repeat(64).getBytes(StandardCharsets.US_ASCII));
            String contextString = "TLS 1.3, " + (client? "client": "server") + " CertificateVerify";
            signatureInput.write(contextString.getBytes(StandardCharsets.US_ASCII));
            signatureInput.write(0x00);
            signatureInput.write(content);
        } catch (IOException e) {
            // Impossible
            throw new RuntimeException();
        }

        try {
            Signature signatureAlgorithm = getSignatureAlgorithm(signatureScheme);
            signatureAlgorithm.initSign(certificatePrivateKey);
            signatureAlgorithm.update(signatureInput.toByteArray());
            byte[] digitalSignature = signatureAlgorithm.sign();
            return digitalSignature;
        }
        catch (SignatureException e) {
            // sign() throws SignatureException: if this signature object is not initialized properly or if this
            //                                   signature algorithm is unable to process the input data provided.
            throw new RuntimeException();
        } catch (InvalidKeyException e) {
            throw new InternalErrorAlert("invalid private key");
        }
    }

    // https://tools.ietf.org/html/rfc8446#section-4.4.4
    protected byte[] computeFinishedVerifyData(byte[] transcriptHash, byte[] baseKey) {
        short hashLength = state.getHashLength();
        byte[] finishedKey = state.hkdfExpandLabel(baseKey, "finished", "", hashLength);
        String macAlgorithmName = "HmacSHA" + (hashLength * 8);
        SecretKeySpec hmacKey = new SecretKeySpec(finishedKey, macAlgorithmName);

        try {
            Mac hmacAlgorithm = Mac.getInstance(macAlgorithmName);
            hmacAlgorithm.init(hmacKey);
            hmacAlgorithm.update(transcriptHash);
            byte[] hmac = hmacAlgorithm.doFinal();
            return hmac;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing " + macAlgorithmName + " support");
        } catch (InvalidKeyException e) {
            throw new RuntimeException();
        }
    }

    protected Signature getSignatureAlgorithm(TlsConstants.SignatureScheme signatureScheme) throws HandshakeFailureAlert {
        Signature signatureAlgorithm = null;
        // https://tools.ietf.org/html/rfc8446#section-9.1
        // "A TLS-compliant application MUST support digital signatures with rsa_pkcs1_sha256 (for certificates),
        // rsa_pss_rsae_sha256 (for CertificateVerify and certificates), and ecdsa_secp256r1_sha256."
        if (signatureScheme.equals(rsa_pss_rsae_sha256)) {
            try {
                signatureAlgorithm = Signature.getInstance(algorithmMapping.get("RSASSA-PSS", 256));
                signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
            }
            catch (NoSuchAlgorithmException e) {
                noRsaSsaPssSupport();
            }
            catch (InvalidAlgorithmParameterException e) {
                // Fairly impossible (because the parameters is hard coded)
                throw new RuntimeException(e);
            }
        }
        else if (signatureScheme.equals(rsa_pss_rsae_sha384)) {
            try {
                signatureAlgorithm = Signature.getInstance(algorithmMapping.get("RSASSA-PSS", 384));
                signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1));
            }
            catch (NoSuchAlgorithmException e) {
                noRsaSsaPssSupport();
            }
            catch (InvalidAlgorithmParameterException e) {
                // Fairly impossible (because the parameters is hard coded)
                throw new RuntimeException(e);
            }
        }
        else if (signatureScheme.equals(rsa_pss_rsae_sha512)) {
            try {
                signatureAlgorithm = Signature.getInstance(algorithmMapping.get("RSASSA-PSS", 512));
                signatureAlgorithm.setParameter(new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1));
            }
            catch (NoSuchAlgorithmException e) {
                noRsaSsaPssSupport();
            }
            catch (InvalidAlgorithmParameterException e) {
                // Fairly impossible (because the parameters is hard coded)
                throw new RuntimeException(e);
            }
        }
        else if (signatureScheme.equals(ecdsa_secp256r1_sha256)) {
            try {
                signatureAlgorithm = Signature.getInstance("SHA256withECDSA");
                // Note that SHA256withECDSA excepts any EC public key, so additional check on the key's curve is necessary
            }
            catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing SHA256withECDSA support");
            }
        }
        else if (signatureScheme.equals(ecdsa_secp384r1_sha384)) {
            try {
                signatureAlgorithm = Signature.getInstance("SHA384withECDSA");
                // Note that SHA384withECDSA excepts any EC public key, so additional check on the key's curve is necessary
            }
            catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing SHA384withECDSA support");
            }
        }
        else if (signatureScheme.equals(ecdsa_secp521r1_sha512)) {
            try {
                signatureAlgorithm = Signature.getInstance("SHA512withECDSA");
                // Note that SHA512withECDSA excepts any EC public key, so additional check on the key's curve is necessary
            }
            catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Missing SHA512withECDSA support");
            }
        }
        else {
            // Bad luck, not (yet) supported.
            throw new HandshakeFailureAlert("Signature algorithm not supported " + signatureScheme);
        }
        return signatureAlgorithm;
    }

    private static void noRsaSsaPssSupport() {
        boolean runningOnAndroid = System.getProperty("java.vendor") != null && System.getProperty("java.vendor").contains("Android");
        String msg = "Missing RSASSA-PSS support";
        if (runningOnAndroid) {
            msg += ". Did you set PlatformMapping.usePlatformMapping(PlatformMapping.Platform.Android)?";
        }
        throw new RuntimeException(msg);
    }

    @Override
    public byte[] getClientEarlyTrafficSecret() {
        if (state != null) {
            return state.getClientEarlyTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientHandshakeTrafficSecret() {
        if (state != null) {
            return state.getClientHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerHandshakeTrafficSecret() {
        if (state != null) {
            return state.getServerHandshakeTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getClientApplicationTrafficSecret() {
        if (state != null) {
            return state.getClientApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    @Override
    public byte[] getServerApplicationTrafficSecret() {
        if (state != null) {
            return state.getServerApplicationTrafficSecret();
        }
        else {
            throw new IllegalStateException("Traffic secret not yet available");
        }
    }

    protected boolean recognizedExtension(Extension extension) {
        return ! (extension instanceof UnknownExtension);
    }
}
