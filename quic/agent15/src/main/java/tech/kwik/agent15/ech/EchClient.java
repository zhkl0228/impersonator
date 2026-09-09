/*
 * Copyright © 2026 zhkl0228
 *
 * This file is part of impersonator (https://github.com/zhkl0228/impersonator), which adds
 * Encrypted Client Hello (RFC 9849) to Agent15, an implementation of TLS 1.3 in Java.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package tech.kwik.agent15.ech;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.tls.EchConfig;
import org.bouncycastle.tls.EchConfigList;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.engine.impl.TlsState;
import tech.kwik.agent15.extension.Extension;
import tech.kwik.agent15.extension.RawExtension;
import tech.kwik.agent15.handshake.ClientHello;
import tech.kwik.agent15.handshake.ServerHello;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Client side Encrypted Client Hello, RFC 9849.
 * <p>
 * Holds the two ClientHellos of one connection: the ClientHelloInner, which carries the real server
 * name and goes into the handshake transcript if the server accepted, and the ClientHelloOuter,
 * which carries the ECHConfig's public name and is the message that goes on the wire. Both are kept
 * because which of the two the transcript hashes is only known once the ServerHello has arrived.
 * <p>
 * Not implemented, and refused rather than guessed at: HelloRetryRequest (agent15 does not implement
 * it at all), ECH with a PSK, and the "ech_outer_extensions" compression, which RFC 9849 section 5.1
 * makes optional and whose only cost is a larger ClientHelloOuter.
 * <p>
 * The HPKE context is deliberately not retained: it would only be needed to answer a
 * HelloRetryRequest.
 */
public class EchClient {

    /** RFC 9849 section 6.1, the first half of the HPKE info string. */
    private static final byte[] INFO_PREFIX = "tls ech".getBytes(StandardCharsets.US_ASCII);

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final String serverName;
    private final EchConfig config;
    private final ClientHello innerClientHello;
    private final ClientHello outerClientHello;

    private boolean accepted;

    private EchClient(String serverName, EchConfig config, ClientHello innerClientHello, ClientHello outerClientHello) {
        this.serverName = serverName;
        this.config = config;
        this.innerClientHello = innerClientHello;
        this.outerClientHello = outerClientHello;
    }

    /**
     * Build the ClientHelloInner and the ClientHelloOuter.
     *
     * @param serverName      the real server name, which only the ClientHelloInner carries.
     * @param echConfigList   the raw ECHConfigList published for <code>serverName</code>.
     * @param extraExtensions the extensions the caller asked for; both messages get them, plus their
     *                        own "encrypted_client_hello".
     */
    public static EchClient create(String serverName, byte[] echConfigList, PublicKey publicKey,
                                   List<TlsConstants.CipherSuite> supportedCiphers,
                                   List<TlsConstants.SignatureScheme> supportedSignatures,
                                   TlsConstants.NamedGroup ecCurve, List<Extension> extraExtensions) {
        EchConfig config = selectConfig(echConfigList);
        int cipherSuite = selectCipherSuite(config);
        int kdfId = cipherSuite >>> 16, aeadId = cipherSuite & 0xffff;

        // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1
        // "It MUST include the "encrypted_client_hello" extension of type inner"
        List<Extension> innerExtensions = new ArrayList<>(extraExtensions);
        innerExtensions.add(EncryptedClientHelloExtension.createInner());
        ClientHello innerClientHello = new ClientHello(serverName, publicKey, false, supportedCiphers,
                supportedSignatures, ecCurve, innerExtensions, null, ClientHello.PskKeyEstablishmentMode.PSKwithDHE);

        byte[] encodedInner = encodeClientHelloInner(innerClientHello, serverName, config);

        HPKE hpke = new HPKE(HPKE.mode_base, (short) EchConfig.KEM_DHKEM_X25519_HKDF_SHA256, (short) kdfId,
                (short) aeadId);
        HPKEContextWithEncapsulation hpkeContext;
        try {
            AsymmetricKeyParameter publicKeyR = hpke.deserializePublicKey(config.getPublicKey());
            hpkeContext = hpke.setupBaseS(publicKeyR, createInfo(config));
        }
        catch (RuntimeException e) {
            // deserializePublicKey and the X25519 agreement report a bad ECHConfig key unchecked.
            throw new EchException("HPKE setup failed for " + config.describe(), e);
        }

        EncryptedClientHelloExtension outerEch = EncryptedClientHelloExtension.createOuter(kdfId, aeadId,
                config.getConfigId(), hpkeContext.getEncapsulation(),
                encodedInner.length + EncryptedClientHelloExtension.AEAD_TAG_LENGTH);

        // https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1
        // "It SHOULD place the value of ECHConfig.contents.public_name in the "server_name" extension."
        List<Extension> outerExtensions = new ArrayList<>(extraExtensions);
        outerExtensions.add(outerEch);
        ClientHello outerClientHello = new ClientHello(config.getPublicName(), publicKey, false, supportedCiphers,
                supportedSignatures, ecCurve, outerExtensions, null, ClientHello.PskKeyEstablishmentMode.PSKwithDHE,
                aad -> seal(hpkeContext, aad, encodedInner, outerEch.getPayloadLength(), config));

        return new EchClient(serverName, config, innerClientHello, outerClientHello);
    }

    /**
     * Build the two ClientHellos from a {@link ClientHelloSpec}, through a factory that knows how.
     * <p>
     * The same as {@link #create} above, except that what the two messages look like is dictated
     * rather than assembled here: this decides only what makes them an inner and an outer - which
     * name each carries, which "encrypted_client_hello" each carries, and that the outer's payload is
     * the sealed inner.
     */
    public static EchClient create(String serverName, byte[] echConfigList, EchClientHelloFactory factory) {
        EchConfig config = selectConfig(echConfigList);
        int cipherSuite = selectCipherSuite(config);
        int kdfId = cipherSuite >>> 16, aeadId = cipherSuite & 0xffff;

        /*
         * Section 5.1: the extensions the ClientHelloOuter repeats verbatim are moved to the end of
         * the ClientHelloInner, so that they form the one contiguous run that may be replaced by a
         * single "ech_outer_extensions" reference. Their relative order is kept, which is what the
         * requirement that they appear in the same relative order in the ClientHelloOuter amounts to.
         * The server rebuilds the ClientHelloInner this way round, so this order is the one that goes
         * into the transcript.
         */
        List<Extension> innerExtensions = groupCompressible(
                factory.createExtensions(serverName, EncryptedClientHelloExtension.createInner()));

        byte[] innerRandom = new byte[32];
        SECURE_RANDOM.nextBytes(innerRandom);
        ClientHello innerClientHello = factory.createClientHello(innerRandom, innerExtensions, null);

        /*
         * The same message again, with that run replaced by the reference. This and not the one above
         * is what gets encrypted; without it the ClientHelloOuter carries a second copy of every
         * extension, which for a browser's ClientHello - a post-quantum key share alone is over a
         * kilobyte - is the difference between two Initial packets and four.
         */
        ClientHello encodedClientHello = factory.createClientHello(innerRandom, compress(innerExtensions), null);
        byte[] encodedInner = encodeClientHelloInner(encodedClientHello, serverName, config);

        HPKE hpke = new HPKE(HPKE.mode_base, (short) EchConfig.KEM_DHKEM_X25519_HKDF_SHA256, (short) kdfId,
                (short) aeadId);
        HPKEContextWithEncapsulation hpkeContext;
        try {
            AsymmetricKeyParameter publicKeyR = hpke.deserializePublicKey(config.getPublicKey());
            hpkeContext = hpke.setupBaseS(publicKeyR, createInfo(config));
        }
        catch (RuntimeException e) {
            throw new EchException("HPKE setup failed for " + config.describe(), e);
        }

        EncryptedClientHelloExtension outerEch = EncryptedClientHelloExtension.createOuter(kdfId, aeadId,
                config.getConfigId(), hpkeContext.getEncapsulation(),
                encodedInner.length + EncryptedClientHelloExtension.AEAD_TAG_LENGTH);

        byte[] outerRandom = new byte[32];
        SECURE_RANDOM.nextBytes(outerRandom);
        ClientHello outerClientHello = factory.createClientHello(outerRandom,
                factory.createExtensions(config.getPublicName(), outerEch),
                aad -> seal(hpkeContext, aad, encodedInner, outerEch.getPayloadLength(), config));

        return new EchClient(serverName, config, innerClientHello, outerClientHello);
    }

    /**
     * RFC 9849 section 5.1: the extension the compressed run is replaced by.
     * <pre>
     * enum { ech_outer_extensions(0xfd00), (65535) } ExtensionType;
     * ExtensionType OuterExtensions&lt;2..254&gt;;
     * </pre>
     * It may appear only in the EncodedClientHelloInner, never in either ClientHello.
     */
    private static final int EXT_ech_outer_extensions = 0xfd00;

    /**
     * @return true if the ClientHelloOuter carries this extension byte for byte, so the
     *         ClientHelloInner can borrow it. Only the server name and the
     *         "encrypted_client_hello" differ between the two; everything else is the same list.
     */
    private static boolean isShared(Extension extension) {
        int type = extension.getType() & 0xffff;
        return type != (TlsConstants.ExtensionType.server_name.value & 0xffff)
                && type != EncryptedClientHelloExtension.TYPE;
    }

    /** Moves the borrowable extensions to the end, keeping their relative order. */
    private static List<Extension> groupCompressible(List<Extension> extensions) {
        List<Extension> uncompressed = new ArrayList<>(), compressible = new ArrayList<>();
        for (Extension extension : extensions) {
            (isShared(extension)? compressible: uncompressed).add(extension);
        }
        uncompressed.addAll(compressible);
        return uncompressed;
    }

    /** The EncodedClientHelloInner form: the grouped run dropped and one reference put in its place. */
    private static List<Extension> compress(List<Extension> innerExtensions) {
        List<Extension> compressed = new ArrayList<>();
        List<Integer> borrowed = new ArrayList<>();
        for (Extension extension : innerExtensions) {
            if (isShared(extension)) {
                borrowed.add(extension.getType() & 0xffff);
            }
            else {
                compressed.add(extension);
            }
        }
        if (borrowed.isEmpty()) {
            return innerExtensions;
        }
        if (borrowed.size() > 127) {
            throw new EchException("OuterExtensions may name at most 127 extensions, got " + borrowed.size());
        }

        ByteBuffer buffer = ByteBuffer.allocate(1 + borrowed.size() * 2);
        buffer.put((byte) (borrowed.size() * 2));
        for (int type : borrowed) {
            if (type == EncryptedClientHelloExtension.TYPE) {
                // Section 5.1: referencing it is a protocol violation the server must reject.
                throw new EchException("OuterExtensions must not reference encrypted_client_hello");
            }
            buffer.putShort((short) type);
        }
        compressed.add(new RawExtension(EXT_ech_outer_extensions, buffer.array()));
        return compressed;
    }

    private static EchConfig selectConfig(byte[] echConfigList) {
        try {
            return EchConfigList.select(echConfigList);
        }
        catch (IOException e) {
            throw new EchException(e.getMessage(), e);
        }
    }

    private static int selectCipherSuite(EchConfig config) {
        try {
            return config.selectCipherSuite();
        }
        catch (IOException e) {
            throw new EchException(e.getMessage(), e);
        }
    }

    private static byte[] seal(HPKEContextWithEncapsulation hpkeContext, byte[] aad, byte[] encodedInner,
                               int expectedLength, EchConfig config) {
        byte[] payload;
        try {
            payload = hpkeContext.seal(aad, encodedInner);
        }
        catch (InvalidCipherTextException e) {
            throw new EchException("HPKE seal failed for " + config.describe(), e);
        }
        if (payload.length != expectedLength) {
            throw new EchException("HPKE seal produced " + payload.length + " bytes, expected " + expectedLength
                    + "; the ClientHelloOuterAAD would not match. " + config.describe());
        }
        return payload;
    }

    /** RFC 9849 section 6.1: {@code "tls ech" || 0x00 || ECHConfig}. */
    private static byte[] createInfo(EchConfig config) {
        byte[] encoded = config.getEncoded();
        byte[] info = new byte[INFO_PREFIX.length + 1 + encoded.length];
        System.arraycopy(INFO_PREFIX, 0, info, 0, INFO_PREFIX.length);
        info[INFO_PREFIX.length] = 0x00;
        System.arraycopy(encoded, 0, info, INFO_PREFIX.length + 1, encoded.length);
        return info;
    }

    /**
     * RFC 9849 section 5.1: the ClientHelloInner without its four byte handshake header and with an
     * empty legacy_session_id, padded as section 6.1.3 recommends.
     * <p>
     * The legacy_session_id is already empty: this is QUIC, where RFC 9001 section 8.4 forbids the
     * TLS 1.3 compatibility mode, and the engine refuses to offer ECH when it is on. So the copy the
     * section asks for is the message itself.
     */
    private static byte[] encodeClientHelloInner(ClientHello innerClientHello, String serverName, EchConfig config) {
        if (innerClientHello.getSessionId().length != 0) {
            throw new EchException("the ClientHelloInner has a " + innerClientHello.getSessionId().length
                    + " byte legacy_session_id; EncodedClientHelloInner needs it empty, and the ClientHelloOuter"
                    + " would have to echo it");
        }

        byte[] message = innerClientHello.getBytes();

        // 1. "If the ClientHelloInner contained a "server_name" extension with a name of length D,
        //     add max(0, M - D) bytes of padding."
        int namePadding = Math.max(0, config.getMaximumNameLength() - serverName.length());
        // 2. "Let N = 31 - ((L - 1) % 32) and add N bytes of padding."
        int length = message.length - 4 + namePadding;
        int blockPadding = 31 - ((length - 1) % 32);

        byte[] encoded = new byte[length + blockPadding];
        System.arraycopy(message, 4, encoded, 0, message.length - 4);
        return encoded;
    }

    /**
     * RFC 9849 section 6.1.4 and 7.2: the server signals acceptance by putting
     * <pre>
     * accept_confirmation = HKDF-Expand-Label(HKDF-Extract(0, ClientHelloInner.random),
     *                                         "ech accept confirmation", transcript_ech_conf, 8)
     * </pre>
     * in the last 8 bytes of ServerHello.random, where transcript_ech_conf is the transcript hash of
     * the ClientHelloInner and this same ServerHello with those 8 bytes zeroed.
     *
     * @param state a TlsState for the cipher suite the server selected; only its HKDF is used, which
     *              is the one keyed by the transcript hash function this computation needs.
     */
    public void processAcceptConfirmation(TlsState state, ServerHello serverHello) {
        byte[] message = serverHello.getBytes();
        int randomOffset = 4 + 2;
        if (message.length < randomOffset + 32) {
            throw new IllegalArgumentException("ServerHello is " + message.length
                    + " bytes, too short to hold a random");
        }

        byte[] confirmationMessage = message.clone();
        Arrays.fill(confirmationMessage, randomOffset + 24, randomOffset + 32, (byte) 0);

        short hashLength = state.getHashLength();
        byte[] transcriptEchConf = hash(hashLength, innerClientHello.getBytes(), confirmationMessage);

        byte[] extracted = state.hkdfExtract(new byte[hashLength], innerClientHello.getClientRandom());
        byte[] expected = state.hkdfExpandLabel(extracted, "ech accept confirmation", transcriptEchConf, (short) 8);

        accepted = MessageDigest.isEqual(expected,
                Arrays.copyOfRange(serverHello.getRandom(), 24, 32));
    }

    private static byte[] hash(short hashLength, byte[] first, byte[] second) {
        String algorithm = "SHA-" + (hashLength * 8);
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance(algorithm);
        }
        catch (NoSuchAlgorithmException e) {
            throw new EchException("Missing " + algorithm + " support", e);
        }
        digest.update(first);
        digest.update(second);
        return digest.digest();
    }

    /** Whether the server accepted the ClientHelloInner. Only meaningful after the ServerHello. */
    public boolean isAccepted() {
        return accepted;
    }

    /** The real server name, the one the ClientHelloInner carries. */
    public String getServerName() {
        return serverName;
    }

    /** The name the ClientHelloOuter sent, and the one the certificate names when ECH is rejected. */
    public String getPublicName() {
        return config.getPublicName();
    }

    /** A one line summary of the offered ECHConfig, for exception messages. */
    public String describeConfig() {
        return config.describe();
    }

    /** The message the transcript hashes when the server accepted. */
    public ClientHello getInnerClientHello() {
        return innerClientHello;
    }

    /** The message that goes on the wire, and that the transcript hashes when the server rejected. */
    public ClientHello getOuterClientHello() {
        return outerClientHello;
    }
}
