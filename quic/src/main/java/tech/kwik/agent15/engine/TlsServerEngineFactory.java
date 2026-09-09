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
package tech.kwik.agent15.engine;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.compat.InputStreamCompat;
import tech.kwik.agent15.engine.impl.TlsServerEngineImpl;
import tech.kwik.agent15.engine.impl.TlsSessionRegistryImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.stream.Collectors;

import static tech.kwik.agent15.TlsConstants.SignatureScheme.*;

public class TlsServerEngineFactory {

    /**
     * https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.3
     * "/* ECDSA algorithms  * /
     *    ecdsa_secp256r1_sha256(0x0403),
     *    ecdsa_secp384r1_sha384(0x0503),
     *    ecdsa_secp521r1_sha512(0x0603),"
     */
    private static final List<String> SUPPORTED_EC_CURVES = List.of("secp256r1", "secp384r1", "secp521r1");

    private final List<X509Certificate> certificateChain;
    private final PrivateKey certificateKey;
    private final TlsSessionRegistry tlsSessionRegistry = new TlsSessionRegistryImpl();
    private final List<TlsConstants.SignatureScheme> preferredSignatureSchemes;

    /**
     * Creates a tls server engine factory, given an RSA certificate and its private key.
     * @param certificateFile
     * @param certificateKeyFile
     * @throws IOException
     * @throws CertificateException
     * @throws InvalidKeySpecException
     * @deprecated
     */
    @Deprecated
    public TlsServerEngineFactory(InputStream certificateFile, InputStream certificateKeyFile) throws IOException, CertificateException, InvalidKeySpecException {
        this(readCertificates(certificateFile), readPrivateKey(certificateKeyFile), null);
    }

    /**
     * Creates a tls server engine factory, extracting certificate and private key from the given keystore
     * @param keyStore      keystore containing the server certificate and its private key
     * @param alias         the alias of the certificate
     * @param keyPassword   the password for the private key
     * @throws CertificateException  when the certificate signature algorithm is not supported or cannot (completely) be determined.
     */
    public TlsServerEngineFactory(KeyStore keyStore, String alias, char[] keyPassword) throws CertificateException {
        this(getCertificates(keyStore, alias), getPrivateKey(keyStore, alias, keyPassword), null);
    }

    /**
     * Creates a tls server engine factory, extracting certificate and private key from the given keystore
     * @param keyStore      keystore containing the server certificate and its private key
     * @param alias         the alias of the certificate
     * @param keyPassword   the password for the private key
     * @param ecCurve       the curve name for ECDSA certificates (in case it cannot be derived from the certificate), or null for RSA certificates
     * @throws CertificateException  when the certificate signature algorithm is not supported or cannot (completely) be determined.
     * @deprecated The EC curve is now determined automatically from the certificate in a provider independent way, so
     * the {@code ecCurve} argument is no longer needed. Use {@link #TlsServerEngineFactory(KeyStore, String, char[])} instead.
     */
    @Deprecated
    public TlsServerEngineFactory(KeyStore keyStore, String alias, char[] keyPassword, String ecCurve) throws CertificateException {
        this(getCertificates(keyStore, alias), getPrivateKey(keyStore, alias, keyPassword), ecCurve);
    }

    private TlsServerEngineFactory(List<X509Certificate> certificateChain, PrivateKey certificateKey, String ecCurve) throws CertificateException {
        this.certificateChain = certificateChain;
        this.certificateKey = certificateKey;
        preferredSignatureSchemes = preferredSignatureSchemes(certificateChain.get(0), ecCurve);
    }

    private static List<X509Certificate> getCertificates(KeyStore keyStore, String alias) {
        try {
            Certificate[] certificates = keyStore.getCertificateChain(alias);
            if (certificates == null) {
                throw new IllegalArgumentException("No certificate found for alias " + alias);
            }
            return Arrays.stream(certificates)
                    .map(c -> (X509Certificate) c)
                    .collect(Collectors.toList());
        }
        catch (KeyStoreException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static PrivateKey getPrivateKey(KeyStore keyStore, String alias, char[] password) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        }
        catch (KeyStoreException | UnrecoverableKeyException e) {
            throw new IllegalArgumentException(e);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Algorithm not supported", e);
        }
    }

    public TlsServerEngine createServerEngine(ServerMessageSender serverMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        TlsServerEngineImpl tlsServerEngine = new TlsServerEngineImpl(certificateChain, certificateKey, preferredSignatureSchemes, serverMessageSender, tlsStatusHandler, tlsSessionRegistry);
        tlsServerEngine.addSupportedCiphers(List.of(TlsConstants.CipherSuite.TLS_AES_128_GCM_SHA256));
        return tlsServerEngine;
    }

    /**
     * Disposes resources uses by this factory.
     * This will actually shut down the session registry associated with this factory, effectively disabling session resumption.
     */
    public void dispose() {
        tlsSessionRegistry.shutdown();
    }

    /**
     * Determines the preferred signature schemes for the given certificate.
     * @param certificate
     * @param ecCurve
     * @return
     * @throws CertificateException  when the certificate signature algorithm is not supported or cannot (completely) be determined.
     * For example, Java has no proper way to get the curve name from an EC public key, so in some cases it cannot be determined.
     * In that case, the curve name should be provided as an argument.
     */
    static List<TlsConstants.SignatureScheme> preferredSignatureSchemes(X509Certificate certificate, String ecCurve) throws CertificateException {
        LinkedHashSet<TlsConstants.SignatureScheme> preferred = new LinkedHashSet<>();
        String algorithm = certificate.getPublicKey().getAlgorithm();
        if (algorithm.equals("RSA")) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) certificate.getPublicKey();
            int keySize = rsaPublicKey.getModulus().bitLength();
            if (keySize <= 2048) {
                preferred.add(rsa_pss_rsae_sha256);
            }
            else if (keySize >= 4096) {
                preferred.add(rsa_pss_rsae_sha512);
            }
            else {
                preferred.add(rsa_pss_rsae_sha384);
            }
            // And add all the others (without duplicates => LinkedHashSet)
            preferred.addAll(List.of(rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512));
        }
        else if (algorithm.equals("EC")) {
            String curveName = ecCurve != null? ecCurve: determineCurveName(certificate);
            if (curveName != null) {
                // https://cabforum.org/working-groups/server/baseline-requirements/documents/
                // 7.1.3.2.2 ECDSA:
                // "If the signing key is P‐256, the signature MUST use ECDSA with SHA‐256."
                // "If the signing key is P‐384, the signature MUST use ECDSA with SHA‐384."
                // "If the signing key is P‐521, the signature MUST use ECDSA with SHA‐512."
                switch (curveName) {
                    case "secp256r1":
                        preferred.add(ecdsa_secp256r1_sha256);
                        break;
                    case "secp384r1":
                        preferred.add(ecdsa_secp384r1_sha384);
                        break;
                    case "secp521r1":
                        preferred.add(ecdsa_secp521r1_sha512);
                        break;
                    default:
                        throw new CertificateException("Unsupported EC curve " + curveName);
                }
            }
            else {
                throw new CertificateException("Unable to extract EC curve name from certificate (with public key: " + certificate.getPublicKey() + ")");
            }
        }
        else {
            throw new CertificateException("Unsupported certificate type " + algorithm);
        }
        return new ArrayList(preferred);
    }

    /**
     * Determines the standard name of the curve used by the given certificate's EC public key.
     *
     * Java does not expose the curve name of an EC public key directly, so instead of parsing the (provider specific)
     * string representation of the parameters, the key's actual curve parameters are compared against those of the
     * known/supported named curves. These named curve parameters are obtained via the standard AlgorithmParameters API,
     * which makes this approach provider independent.
     *
     * @return the matching curve name, or null if the key does not use any of the supported curves.
     */
    private static String determineCurveName(Certificate certificate) {
        ECParameterSpec keyParams = ((ECPublicKey) certificate.getPublicKey()).getParams();
        return SUPPORTED_EC_CURVES.stream()
                .filter(curveName -> matchesNamedCurve(keyParams, curveName))
                .findFirst()
                .orElse(null);
    }

    private static boolean matchesNamedCurve(ECParameterSpec keyParams, String curveName) {
        try {
            AlgorithmParameters algorithmParameters = AlgorithmParameters.getInstance("EC");
            algorithmParameters.init(new ECGenParameterSpec(curveName));
            ECParameterSpec namedCurve = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            // EllipticCurve and ECPoint implement equals(), so the curve parameters can be compared exactly.
            return keyParams.getCurve().equals(namedCurve.getCurve())
                    && keyParams.getGenerator().equals(namedCurve.getGenerator())
                    && keyParams.getOrder().equals(namedCurve.getOrder())
                    && keyParams.getCofactor() == namedCurve.getCofactor();
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            return false;
        }
    }

    private static List<X509Certificate> readCertificates(InputStream file) throws IOException, CertificateException {
        String fileContent = new String(InputStreamCompat.readAllBytes(file), Charset.defaultCharset());
        String[] chunks = fileContent.split("-----END CERTIFICATE-----\n");

        List<X509Certificate> certs = new ArrayList<>();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        for (int i = 0; i < chunks.length; i++) {
            if (chunks[i].startsWith("-----BEGIN CERTIFICATE-----")) {
                String encodedCertificate = chunks[i]
                        .replace("-----BEGIN CERTIFICATE-----", "")
                        .replaceAll(System.lineSeparator(), "")
                        .replace("-----END CERTIFICATE-----", "");
                Certificate certificate = certificateFactory.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(encodedCertificate)));
                certs.add((X509Certificate) certificate);
            }
        }

        return certs;
    }

    private static RSAPrivateKey readPrivateKey(InputStream file) throws IOException, InvalidKeySpecException {
        String key = new String(InputStreamCompat.readAllBytes(file), Charset.defaultCharset());

        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "");
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Missing key algorithm RSA");
        }
    }
}
