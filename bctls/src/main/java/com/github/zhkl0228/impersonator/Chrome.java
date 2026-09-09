package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Chrome v152, which is the same browser on every platform. Captures from macOS and Android produce
 * identical JA3, JA4 and peetprint values; what differs is the user agent, the two client hints that
 * name the platform, and the trust anchor list, which follows the platform's root store.
 */
abstract class Chrome extends ImpersonatorFactory {

    private static final String CIPHER_SUITES =
            "GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53";

    /** Chrome varies the "Not?A_Brand" entry between releases, so this is kept as captured. */
    private static final String BRANDS =
            "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"";

    private static final String ACCEPT =
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";

    /**
     * "trust_anchors", draft-ietf-tls-trust-anchor-ids. Not in {@link ExtensionType} because
     * BouncyCastle does not implement the draft.
     */
    private static final int EXT_trust_anchors = 51764;

    /** The value of the Sec-Ch-Ua-Platform client hint, quotes included. */
    private final String platform;

    private final boolean mobile;

    Chrome(String userAgent, String platform, boolean mobile) {
        super(CIPHER_SUITES, userAgent, true);
        this.platform = platform;
        this.mobile = mobile;
    }

    /**
     * The trust anchor ids this build advertises: a list of relative OIDs naming the CAs in the
     * root store it uses. Fixed for a given build rather than generated per connection - repeated
     * captures from one browser are byte identical - so it has to be refreshed when the root store
     * is.
     */
    protected abstract byte[] getTrustAnchors();

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        /*
         * Insertion order is the order they go on the wire. Chrome puts the client hints first and
         * the user agent only after Upgrade-Insecure-Requests, so it has to be taken out and put
         * back rather than left where the interceptor placed it.
         */
        String userAgent = headers.remove("User-Agent");
        headers.put("Sec-Ch-Ua", BRANDS);
        headers.put("Sec-Ch-Ua-Mobile", mobile ? "?1" : "?0");
        headers.put("Sec-Ch-Ua-Platform", "\"" + platform + "\"");
        headers.put("Upgrade-Insecure-Requests", "1");
        if (userAgent != null) {
            headers.put("User-Agent", userAgent);
        }
        headers.put("Accept", ACCEPT);
        // services/network/sec_header_helpers.cc sets these as Site, Mode, User, Dest.
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Accept-Encoding", "gzip, deflate, br, zstd");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Priority", "u=0, i");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        http2Connection.setSetting(Settings.HEADER_TABLE_SIZE, 65536);
        http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 6291456);
        http2Connection.setSetting(Settings.MAX_HEADER_LIST_SIZE, 262144);
        http2Connection.setWindowSizeIncrement(15663105L);
        http2Connection.setHeaderOrder("m,a,s,p");
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] {
                NamedGroup.X25519MLKEM768,
                NamedGroup.x25519
        };
    }

    /**
     * The ClientHello Chrome sends over QUIC, from a capture of Chrome 152.0.7977.84 against
     * {@code quic.tools.scrapfly.io/api/fp/quic}; the capture is kept verbatim in
     * {@code docs/captures/chrome-152-quic.json}, with a second capture of a resumed connection in
     * {@code chrome-152-quic-resumed.json}.
     * <p>
     * A different message from the TCP one above, which is why it is a separate capture and not
     * derived: no "renegotiation_info", no "session_ticket", no "status_request", no ML-DSA among the
     * signature algorithms, "application_settings" naming h3 rather than h2, TLS 1.3 alone in
     * "supported_versions" where the TCP one also offers 1.2, and a "quic_transport_parameters" that
     * has no counterpart at all.
     * <p>
     * The extension order is shuffled per connection, which is what the second capture in that
     * directory shows when read against the first: same extensions, different order.
     * <p>
     * One thing the captures could not settle: whether this ClientHello carries GREASE cipher suites
     * and extensions the way the TCP one does. The endpoint flags GREASE explicitly in the transport
     * parameters and in the HTTP/3 settings but shows none in the TLS lists, which reads either as
     * "there is none" or as "they are stripped there". So this sends what was observed and no more.
     * It does not change the JA4, which excludes GREASE by definition, but it would change the bytes;
     * a packet capture of the same request is what would answer it.
     */
    @Override
    public QuicClientHello getQuicClientHello() {
        return new QuicClientHello() {

            @Override
            public int[] getCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256
                };
            }

            @Override
            public int[] getKeyShareGroups() {
                return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519 };
            }

            @Override
            public ExtensionOrder onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                        new ProtocolVersion[] { ProtocolVersion.TLSv13 });
                TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions,
                        new short[] { PskKeyExchangeMode.psk_dhe_ke });
                addSignatureAlgorithmsExtension(clientExtensions,
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
                addSupportedGroupsExtension(clientExtensions, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
                        NamedGroup.secp256r1, NamedGroup.secp384r1);
                clientExtensions.put(EXT_trust_anchors, getTrustAnchors());
                TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions,
                        new int[] { CertificateCompressionAlgorithm.brotli });
                // A host that publishes an ECHConfig gets a real one instead, which is not implemented
                // yet for a dictated ClientHello; the engine refuses that combination rather than
                // silently sending one of the two.
                addGreaseEncryptedClientHelloExtension(clientExtensions);
                addApplicationSettingsExtension(clientExtensions, "h3");
                /*
                 * Shuffled, not ordered. Two captures of the same Chrome against the same host give the
                 * same twelve extensions in completely different orders - 43, 45, 57, 16, 13, 51, 0,
                 * 51764, 27, 65037, 17613, 10 and then 17613, 51764, 0, 13, 16, 65037, 43, 27, 42, 57,
                 * 51, 10, 45, 41 - which is BoringSSL permuting them per connection, the same thing the
                 * TCP ClientHello above does. A fixed order would be the one thing here that no real
                 * Chrome ever sends twice.
                 */
                return new ExtensionOrder(null, false);
            }
        };
    }

    /**
     * Both of this browser's ClientHellos are captured - docs/captures/chrome-152-quic.json and
     * chrome-152-quic-resumed.json - so a resumed handshake can be described rather than guessed at.
     * Its extension order is a per-connection shuffle anyway, which the two extra extensions join.
     */
    @Override
    public boolean isQuicSessionResumptionSupported() {
        return true;
    }

    /**
     * The QUIC layer of the same capture.
     * <p>
     * Chrome shuffles the transport parameters - the capture has them in the order 15, 7, 5, 9, 1, 6,
     * 32, 3, GREASE, 8, 0x3128, 17, 4 - so what identifies it is which parameters it sends, not their
     * order. It omits everything that equals the RFC default, hence {@link QuicTransport.Builder#omit}.
     * <p>
     * The last three are the ones Chrome sends that are not RFC 9000's. "version_information"
     * (RFC 9368) offers a reserved version alongside the one in use, which greases version
     * negotiation. The reserved transport parameter greases the parameters themselves, RFC 9287.
     * And 0x3128 is Google's own {@code google_connection_options}, a list of four byte tags that
     * turn on experiments in Google's servers; Chrome sends {@code ORIG}, which Chromium's
     * {@code crypto_protocol.h} documents as "Experiment for sending new ORIGIN frame".
     */
    @Override
    public QuicTransport getQuicTransport() {
        return QuicTransport.newBuilder()
                .destinationConnectionIdLength(8)
                // Zero, from a Wireshark capture of this browser: every Initial it sends carries a
                // source connection id length of 0, and the server's replies come back addressed to
                // a zero length connection id. The fingerprint endpoint reports 4 here whatever the
                // client sends - that 4 is the endpoint's own connection id - which is where the
                // wrong value came from and why no test caught it.
                .sourceConnectionIdLength(0)
                // QUICHE's kDefaultMaxPacketSize. A capture shows every Chrome Initial datagram at
                // 1250 bytes where Safari sends the bare 1200 RFC 9000 section 14.1 requires; the
                // fingerprint endpoint reports 1250 for both and so could not have told us.
                .initialDatagramSize(1250)
                .chaosProtection()
                .initialMaxData(15728640L)
                .initialMaxStreamDataBidirectional(6291456L)
                .initialMaxStreamDataUnidirectional(6291456L)
                .initialMaxStreamsBidirectional(100)
                .initialMaxStreamsUnidirectional(103)
                .maxIdleTimeoutMillis(30000L)
                .maxUdpPayloadSize(1472)
                .maxDatagramFrameSize(65536)
                .omit(QuicTransport.ACK_DELAY_EXPONENT, QuicTransport.MAX_ACK_DELAY,
                        QuicTransport.ACTIVE_CONNECTION_ID_LIMIT)
                .availableVersions(QuicTransport.greaseVersion())
                .googleConnectionOptions("ORIG")
                .greaseParameter()
                .build();
    }

    /**
     * The HTTP/3 SETTINGS of the same capture: {@code 1:65536, 6:262144, 7:100, 51:1} and a GREASE
     * one, in that order.
     * <p>
     * The first and the third are promises, not decoration: they tell the peer's encoder it may keep
     * a 64 KiB dynamic table and let a hundred streams block waiting for entries it has not delivered
     * yet. They are sent because the QPACK decoder underneath now implements that - the dynamic
     * table, both QPACK streams, and the acknowledgements the encoder needs before it will use any of
     * it; see quic/qpack/UPSTREAM.md. The other three cost nothing to mean: MAX_FIELD_SECTION_SIZE is
     * a limit on what this end accepts, H3_DATAGRAM matches the max_datagram_frame_size the transport
     * parameters already advertise, and a GREASE setting is ignored by definition.
     */
    @Override
    public Map<Long, Long> getHttp3Settings() {
        Map<Long, Long> settings = new LinkedHashMap<>();
        settings.put(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 0x10000L);
        settings.put(Http3Settings.MAX_FIELD_SECTION_SIZE, 262144L);
        settings.put(Http3Settings.QPACK_BLOCKED_STREAMS, 100L);
        settings.put(Http3Settings.H3_DATAGRAM, 1L);
        settings.put(Http3Settings.randomGrease(), (long) ThreadLocalRandom.current().nextInt(Integer.MAX_VALUE));
        return settings;
    }

    private static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
        addApplicationSettingsExtension(clientExtensions, "h2");
    }

    private static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions, String protocol) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(16)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            byte[] bytes = protocol.getBytes();
            dataOutput.writeShort(bytes.length + 1);
            dataOutput.writeByte(bytes.length);
            dataOutput.write(bytes);
            clientExtensions.put(ExtensionType.application_settings, baos.toByteArray());
        }
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        randomSupportedVersionsExtension(clientExtensions);
        addSignatureAlgorithmsExtension(clientExtensions,
                SignatureAndHashAlgorithm.create(randomGrease()),
                // Chrome 152 offers the ML-DSA schemes of draft-ietf-tls-mldsa ahead of the classical ones.
                SignatureAndHashAlgorithm.create(SignatureScheme.mldsa44),
                SignatureAndHashAlgorithm.create(SignatureScheme.mldsa65),
                SignatureAndHashAlgorithm.create(SignatureScheme.mldsa87),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512));
        final int supportedGroupGrease = randomGrease();
        addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.X25519MLKEM768,
                NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.brotli});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        addApplicationSettingsExtension(clientExtensions);
        clientExtensions.put(EXT_trust_anchors, getTrustAnchors());
        {
            // Chrome reuses the supported_groups GREASE value for the key share.
            Vector<KeyShareEntry> keyShareEntries = new Vector<>(1);
            keyShareEntries.add(new KeyShareEntry(supportedGroupGrease, new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        return new ExtensionOrder(null, true);
    }
}
