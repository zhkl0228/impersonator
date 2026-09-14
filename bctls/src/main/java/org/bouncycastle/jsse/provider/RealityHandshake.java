package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.RealityConfig;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.ClientHello;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.jcajce.JceX25519;
import org.bouncycastle.tls.crypto.impl.jcajce.RealityTlsCertificate;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Hashtable;

/**
 * The REALITY half of one connection's handshake: it writes the authentication into the ClientHello
 * the client is about to send, and then judges the certificate the server sends back with the key
 * that authentication derived.
 * <p>
 * Follows the server, {@code XTLS/REALITY}'s {@code tls.go}, and the client it documents,
 * {@code Xray-core}'s {@code transport/internet/reality/reality.go}. Every field is fixed by that
 * pair and nothing here is negotiated, so a mismatch is a bug rather than a variant: this class
 * throws where it cannot proceed instead of falling back, because REALITY's own answer to a client
 * it does not recognize is to silently forward the connection to the real website - which arrives
 * here as a certificate that is perfectly valid and simply not the server's.
 *
 * <p>One instance per connection: the authentication key is derived from that connection's
 * ClientHello random and ephemeral key.
 */
final class RealityHandshake {

    private static final Logger log = LoggerFactory.getLogger(RealityHandshake.class);

    /**
     * Where legacy_session_id sits in the ClientHello handshake message, counted from the handshake
     * type byte: 4 (handshake header) + 2 (legacy_version) + 32 (random) + 1 (the length byte).
     * Xray writes the same constant as {@code hello.Raw[39:]}; it is fixed because everything
     * before it is fixed width.
     */
    private static final int SESSION_ID_OFFSET = 39;

    private static final int SESSION_ID_LENGTH = 32;

    /** The authentication plaintext: 3 bytes version, 1 reserved, 4 timestamp, 8 shortId. */
    private static final int PLAINTEXT_LENGTH = 16;

    /** client_random splits in two: the first 20 bytes salt the HKDF, the last 12 are the GCM nonce. */
    private static final int HKDF_SALT_LENGTH = 20;
    private static final int GCM_NONCE_LENGTH = 12;

    private static final byte[] HKDF_INFO = { 'R', 'E', 'A', 'L', 'I', 'T', 'Y' };

    private static final int AUTH_KEY_LENGTH = 32;

    private final RealityConfig config;

    /**
     * Derived while sealing the ClientHello and read again when the certificate arrives. Null until
     * then, which is the state that says the two halves ran out of order.
     */
    private byte[] authKey;

    RealityHandshake(RealityConfig config) {
        this.config = config;
    }

    /**
     * Replace the ClientHello's legacy_session_id with the REALITY authentication, in place.
     * <p>
     * The ciphertext authenticates the whole message, so the order matters: the session_id is zeroed
     * first, the message in that state is the AEAD's additional data, and only then does the
     * ciphertext go where the zeroes were. The server does the same thing in reverse, which is why
     * it can check the ClientHello reached it byte for byte.
     *
     * <p>The ciphertext lands in two places: the encoded message, which is what goes on the wire and
     * into the transcript, and the {@link ClientHello}'s own session_id, which is what the client
     * later compares the ServerHello's legacy_session_id_echo against. Writing only the first leaves
     * the client rejecting the server's echo of its own authentication.
     *
     * @param clientHello      the ClientHello {@code message} was encoded from
     * @param message          the encoded ClientHello, from its handshake type byte
     * @param length           how much of {@code message} is that ClientHello
     * @param clientAgreements the key shares this ClientHello offers, by named group
     */
    void sealClientHello(ClientHello clientHello, byte[] message, int length, Hashtable<?, ?> clientAgreements)
            throws IOException {
        byte[] clientRandom = clientHello.getRandom();
        byte[] sessionId = clientHello.getSessionID();
        if (authKey != null) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "REALITY has already authenticated this connection; a second ClientHello"
                            + " (HelloRetryRequest) is not implemented");
        }
        if (length < SESSION_ID_OFFSET + SESSION_ID_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "ClientHello is " + length + " bytes, too short to hold a session_id at " + SESSION_ID_OFFSET);
        }
        int sessionIdLength = message[SESSION_ID_OFFSET - 1] & 0xff;
        if (sessionIdLength != SESSION_ID_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "REALITY needs the 32 byte legacy_session_id of TLS 1.3 compatibility mode to carry its"
                            + " authentication, but this ClientHello has a " + sessionIdLength + " byte one");
        }
        if (clientRandom == null || clientRandom.length != HKDF_SALT_LENGTH + GCM_NONCE_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.internal_error, "client_random is "
                    + (clientRandom == null ? "null" : clientRandom.length + " bytes") + ", expected 32");
        }
        if (sessionId == null || sessionId.length != SESSION_ID_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.internal_error, "the ClientHello's own session_id is "
                    + (sessionId == null ? "null" : sessionId.length + " bytes") + ", expected "
                    + SESSION_ID_LENGTH + " to match the encoded one");
        }

        byte[] sharedSecret = agreeWithServerPublicKey(clientAgreements);
        this.authKey = hkdf(sharedSecret, Arrays.copyOf(clientRandom, HKDF_SALT_LENGTH));

        byte[] plaintext = authenticationPlaintext();

        // Zero the session_id first: what the server decrypts with is the message in exactly this state.
        java.util.Arrays.fill(message, SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LENGTH, (byte) 0);

        byte[] nonce = Arrays.copyOfRange(clientRandom, HKDF_SALT_LENGTH, clientRandom.length);
        byte[] ciphertext = seal(plaintext, nonce, message, length);
        if (ciphertext.length != SESSION_ID_LENGTH) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "AES-256-GCM produced " + ciphertext.length + " bytes for the session_id, expected "
                            + SESSION_ID_LENGTH);
        }
        System.arraycopy(ciphertext, 0, message, SESSION_ID_OFFSET, SESSION_ID_LENGTH);
        System.arraycopy(ciphertext, 0, sessionId, 0, SESSION_ID_LENGTH);

        if (log.isDebugEnabled()) {
            /*
             * The server prints the same values (realitySettings.show), and a rejection is silent on
             * the wire - it forwards the connection to the target website - so this is the only way
             * to tell which field the two ends disagree about.
             */
            log.debug("REALITY authKey={}, plaintext={}, sessionId={}, aadLength={}, aad={}",
                    Hex.toHexString(authKey), Hex.toHexString(plaintext), Hex.toHexString(ciphertext),
                    length, Hex.toHexString(message, 0, length));
        }
    }

    /**
     * The X25519 shared secret between this ClientHello's ephemeral key and the server's long term
     * public key.
     * <p>
     * The plain x25519 key share is the one to use: a REALITY server reads that one first and only
     * falls back to the X25519 half of X25519MLKEM768 when a ClientHello offers no separate x25519
     * share. Every profile that can speak REALITY offers both, so the choice is never in doubt here.
     */
    private byte[] agreeWithServerPublicKey(Hashtable<?, ?> clientAgreements) throws IOException {
        Object agreement = clientAgreements == null ? null : clientAgreements.get(NamedGroup.x25519);
        if (!(agreement instanceof JceX25519)) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "REALITY needs the x25519 key share's private key to authenticate, but this"
                            + " ClientHello's x25519 agreement is "
                            + (agreement == null ? "absent" : agreement.getClass().getName()));
        }
        TlsSecret secret = ((JceX25519) agreement).agreeWith(config.getPublicKey());
        return secret.extract();
    }

    /** HKDF-SHA256 over the shared secret, which is what turns it into the key both sides use. */
    private byte[] hkdf(byte[] sharedSecret, byte[] salt) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, salt, HKDF_INFO));
        byte[] out = new byte[AUTH_KEY_LENGTH];
        hkdf.generateBytes(out, 0, out.length);
        return out;
    }

    /**
     * The 16 bytes the server decrypts and checks: the client version it compares against its
     * {@code minClientVer}/{@code maxClientVer}, a reserved zero, the seconds it compares against
     * its {@code maxTimeDiff}, and the shortId it looks up in its list.
     */
    private byte[] authenticationPlaintext() {
        byte[] plaintext = new byte[PLAINTEXT_LENGTH];
        int[] version = config.getClientVersion();
        plaintext[0] = (byte) version[0];
        plaintext[1] = (byte) version[1];
        plaintext[2] = (byte) version[2];
        plaintext[3] = 0;
        long seconds = System.currentTimeMillis() / 1000L;
        plaintext[4] = (byte) (seconds >>> 24);
        plaintext[5] = (byte) (seconds >>> 16);
        plaintext[6] = (byte) (seconds >>> 8);
        plaintext[7] = (byte) seconds;
        byte[] shortId = config.getShortId();
        System.arraycopy(shortId, 0, plaintext, 8, shortId.length);
        return plaintext;
    }

    private byte[] seal(byte[] plaintext, byte[] nonce, byte[] additionalData, int additionalDataLength)
            throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", BouncyCastleProvider.PROVIDER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(authKey, "AES"),
                    new GCMParameterSpec(128, nonce));
            cipher.updateAAD(additionalData, 0, additionalDataLength);
            return cipher.doFinal(plaintext);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert(AlertDescription.internal_error, "seal the REALITY session_id", e);
        }
    }

    /**
     * Whether the certificate is the temporary one a REALITY server signs with the key this
     * connection's ClientHello established, rather than the real certificate of the website the
     * server forwards unrecognized connections to.
     * <p>
     * A REALITY server issues a self signed Ed25519 certificate and overwrites its signature with
     * {@code HMAC-SHA512(authKey, ed25519PublicKey)} - a value only something holding the server's
     * private key could have produced, which is the whole authentication. Anything else means this
     * connection was answered by the target website: the server rejected us, or somebody in between
     * redirected the ClientHello.
     */
    void verifyServerCertificate(TlsCertificate certificate) throws IOException {
        if (authKey == null) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "the REALITY certificate arrived before the ClientHello was authenticated");
        }

        if (!(certificate instanceof RealityTlsCertificate)) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "a REALITY connection has to be built on RealityJcaTlsCrypto, but its certificate came"
                            + " back as " + certificate.getClass().getName());
        }
        RealityTlsCertificate realityCertificate = (RealityTlsCertificate) certificate;

        byte[] publicKey = realityCertificate.getEd25519PublicKey();
        byte[] signature = realityCertificate.getSignature();
        byte[] expected = hmacSha512(publicKey);
        if (!Arrays.constantTimeAreEqual(expected, signature)) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate, realityRejected(
                    "the certificate's signature is not HMAC-SHA512(authKey, publicKey)"
                            + "\n  publicKey = " + Hex.toHexString(publicKey)
                            + "\n  signature = " + Hex.toHexString(signature)
                            + "\n  expected  = " + Hex.toHexString(expected)));
        }
    }

    /**
     * Both ways of failing look identical on the wire - a valid certificate for the target website -
     * so the message says what that means rather than only what was seen.
     */
    private String realityRejected(String what) {
        return "REALITY authentication failed and this connection was answered by the target website: "
                + what + ". The server did not recognize us, which means its public key, its shortId list,"
                + " its serverNames, or its clock disagree with " + config;
    }

    private byte[] hmacSha512(byte[] data) throws IOException {
        try {
            Mac mac = Mac.getInstance("HmacSHA512", BouncyCastleProvider.PROVIDER_NAME);
            mac.init(new SecretKeySpec(authKey, "HmacSHA512"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new TlsFatalAlert(AlertDescription.internal_error, "HMAC-SHA512 over the REALITY certificate", e);
        }
    }
}
