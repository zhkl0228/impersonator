package org.bouncycastle.tls.crypto.impl.jcajce;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.SignatureAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.Tls13Verifier;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsVerifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

/**
 * The temporary certificate a REALITY server issues, which no X.509 parser in Java will accept.
 * <p>
 * REALITY signs one with an empty issuer and subject and a validity of year one, because nothing is
 * meant to read it as a certificate: the client authenticates it by recomputing
 * {@code HMAC-SHA512(authKey, publicKey)} over its signature field, and a chain would be beside the
 * point. RFC 5280 section 4.1.2.4 requires a non-empty issuer DN, so BouncyCastle's ASN.1 layer, its
 * CertificateFactory and the JDK's own all reject the encoding outright - Go's {@code crypto/x509},
 * which is what the server and the reference client use, does not.
 * <p>
 * So this reads the three fields the handshake actually needs - the Ed25519 public key, the
 * signature, and the serial number - straight out of the DER, and refuses anything that is not
 * shaped like the certificate REALITY issues. It is not a general X.509 implementation and must not
 * be used as one: there is no chain, no name, no validity and no usage here to check, which is only
 * safe because a REALITY client's whole trust decision is that HMAC.
 *
 * @see <a href="https://github.com/XTLS/REALITY">XTLS/REALITY</a>, {@code handshake_server_tls13.go}
 */
public class RealityTlsCertificate implements TlsCertificate {

    /**
     * A v3 certificate's tbsCertificate opens with an explicit [0] version, which puts the fields
     * that follow one place later than in the v1 encoding REALITY never produces.
     */
    private static final int TBS_VERSION_TAG = 0;

    private static final int TBS_SERIAL_NUMBER = 1;
    private static final int TBS_SUBJECT_PUBLIC_KEY_INFO = 6;

    /** tbsCertificate, signatureAlgorithm, signatureValue. */
    private static final int CERTIFICATE_FIELDS = 3;

    private static final int ED25519_PUBLIC_KEY_LENGTH = 32;

    private final JcaTlsCrypto crypto;
    private final byte[] encoding;
    private final BigInteger serialNumber;
    private final SubjectPublicKeyInfo subjectPublicKeyInfo;
    private final byte[] signature;

    RealityTlsCertificate(JcaTlsCrypto crypto, byte[] encoding) throws IOException {
        this.crypto = crypto;
        this.encoding = encoding;

        ASN1Sequence certificate = ASN1Sequence.getInstance(encoding);
        if (certificate.size() != CERTIFICATE_FIELDS) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, "a Certificate is "
                    + CERTIFICATE_FIELDS + " fields, this one is " + certificate.size());
        }

        ASN1Sequence tbsCertificate = ASN1Sequence.getInstance(certificate.getObjectAt(0));
        ASN1Encodable version = tbsCertificate.getObjectAt(0);
        if (!(version instanceof ASN1TaggedObject)
                || ((ASN1TaggedObject) version).getTagNo() != TBS_VERSION_TAG) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate,
                    "REALITY issues a v3 certificate, and this tbsCertificate has no explicit version");
        }
        this.serialNumber = ASN1Integer.getInstance(tbsCertificate.getObjectAt(TBS_SERIAL_NUMBER)).getValue();
        this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                tbsCertificate.getObjectAt(TBS_SUBJECT_PUBLIC_KEY_INFO));
        requireEd25519(subjectPublicKeyInfo.getAlgorithm(), "public key");

        byte[] publicKey = subjectPublicKeyInfo.getPublicKeyData().getOctets();
        if (publicKey.length != ED25519_PUBLIC_KEY_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, "Ed25519 public key is "
                    + publicKey.length + " bytes: " + Hex.toHexString(publicKey));
        }

        requireEd25519(AlgorithmIdentifier.getInstance(certificate.getObjectAt(1)), "signature");
        this.signature = ASN1BitString.getInstance(certificate.getObjectAt(2)).getOctets();
    }

    /**
     * The message says what a wrong algorithm means, not only what was seen. A REALITY server that
     * does not recognize a client does not answer it: it forwards the connection to the real website,
     * so the certificate that arrives is a valid one belonging to somebody else, and this is where
     * that shows up.
     */
    private static void requireEd25519(AlgorithmIdentifier algorithm, String what) throws IOException {
        if (!EdECObjectIdentifiers.id_Ed25519.equals(algorithm.getAlgorithm())) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, "the server's certificate " + what
                    + " is " + algorithm.getAlgorithm() + " rather than the Ed25519 a REALITY server issues,"
                    + " which is the target website answering: REALITY did not recognize this client, so its"
                    + " public key, its shortId, its serverName or this machine's clock disagree with the server");
        }
    }

    /** The raw 32 byte key the authentication HMAC is taken over. */
    public byte[] getEd25519PublicKey() {
        return subjectPublicKeyInfo.getPublicKeyData().getOctets();
    }

    /** The signature field, which a REALITY server overwrites with that HMAC. */
    public byte[] getSignature() {
        return Arrays.clone(signature);
    }

    public Tls13Verifier createVerifier(int signatureScheme) throws IOException {
        if (SignatureScheme.ed25519 != signatureScheme) {
            throw new TlsFatalAlert(AlertDescription.illegal_parameter,
                    "a REALITY server signs with Ed25519, and this CertificateVerify is "
                            + SignatureScheme.getText(signatureScheme));
        }
        try {
            PublicKey publicKey = crypto.getHelper().createKeyFactory("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded(ASN1Encoding.DER)));
            Signature verifier = crypto.getHelper().createSignature("Ed25519");
            verifier.initVerify(publicKey);
            return new JcaTls13Verifier(verifier);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert(AlertDescription.internal_error, "verify the REALITY CertificateVerify", e);
        }
    }

    public byte[] getEncoded() {
        return Arrays.clone(encoding);
    }

    /**
     * REALITY's certificate carries no extension at all, except the one holding the optional
     * ML-DSA-65 signature, and the handshake asks about none of them: there is no chain to walk and
     * no name to match, so every question about an extension is answered "absent" the same way it
     * would be for a certificate that really has none.
     */
    public byte[] getExtension(ASN1ObjectIdentifier extensionOID) {
        return null;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public String getSigAlgOID() {
        return EdECObjectIdentifiers.id_Ed25519.getId();
    }

    public ASN1Encodable getSigAlgParams() {
        return null;
    }

    public short getLegacySignatureAlgorithm() throws IOException {
        throw new TlsFatalAlert(AlertDescription.internal_error,
                "REALITY is TLS 1.3 only; there is no TLS 1.2 signature algorithm for this certificate");
    }

    public boolean supportsSignatureAlgorithm(short signatureAlgorithm) {
        return SignatureAlgorithm.ed25519 == signatureAlgorithm;
    }

    public boolean supportsSignatureAlgorithmCA(short signatureAlgorithm) {
        return SignatureAlgorithm.ed25519 == signatureAlgorithm;
    }

    /**
     * Nothing to check: the certificate has no keyUsage or extendedKeyUsage extension, and a REALITY
     * client's trust decision is the authentication HMAC rather than anything stated in here.
     */
    public TlsCertificate checkUsageInRole(int tlsCertificateRole) {
        return this;
    }

    public TlsEncryptor createEncryptor(int tlsCertificateRole) throws IOException {
        throw new TlsFatalAlert(AlertDescription.internal_error,
                "a REALITY certificate is only ever used to verify, never to encrypt to");
    }

    public TlsVerifier createVerifier(short signatureAlgorithm) throws IOException {
        throw new TlsFatalAlert(AlertDescription.internal_error,
                "REALITY is TLS 1.3 only; this is the TLS 1.2 verifier");
    }
}
