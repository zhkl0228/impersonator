package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;
import java.util.concurrent.ThreadLocalRandom;

/**
 * macOS Safari v26.6.2 and iOS Safari v26.6. Captures of both are byte identical - same ClientHello,
 * same HTTP/2 settings, same header order, and over QUIC the same JA4, the same HTTP/3 SETTINGS and
 * the same transport parameters - so the only thing that distinguishes them is the user agent.
 * Neither offers Encrypted Client Hello.
 */
class MacSafari extends ImpersonatorFactory {

    static ImpersonatorApi newMacSafari() {
        return new MacSafari("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15");
    }

    static ImpersonatorApi newIOS() {
        return new MacSafari("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1");
    }

    private MacSafari(String userAgent) {
        super(
                "GREASE-4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10",
                userAgent,
                false);
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        /*
         * Insertion order is the order they go on the wire. Safari leads with Sec-Fetch-Dest, ahead
         * of the user agent, so the user agent has to be taken out and put back rather than left
         * where the interceptor placed it. Unlike Chrome and Firefox it sends neither
         * Sec-Fetch-User nor Upgrade-Insecure-Requests.
         */
        String userAgent = headers.remove("User-Agent");
        headers.put("Sec-Fetch-Dest", "document");
        if (userAgent != null) {
            headers.put("User-Agent", userAgent);
        }
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Priority", "u=0, i");
        headers.put("Accept-Encoding", "gzip, deflate, br, zstd");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
        http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 2097152);
        // SETTINGS_NO_RFC7540_PRIORITIES of RFC 9218, which BouncyCastle has no constant for.
        http2Connection.setSetting(9, 1);
        http2Connection.setWindowSizeIncrement(10420225L);
        http2Connection.setHeaderOrder(getPseudoHeaderOrder());
    }

    /** ":method", ":scheme", ":authority", ":path" - asserted against a capture in MacSafariTest. */
    @Override
    public String getPseudoHeaderOrder() {
        return "m,s,a,p";
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519 };
    }

    /**
     * The extensions both of Safari's ClientHellos carry with identical contents: the same ten
     * signature algorithms, the same six named groups, the same key exchange modes and the same
     * certificate compression. They are one browser's, so they are written once - a difference
     * between the TCP and the QUIC ClientHello would have to be a real one, seen in a capture, and
     * these are not.
     *
     * @param greaseGroup the GREASE named group, which the caller also uses for the key share entry
     *                    that goes with it
     */
    private void addSharedExtensions(Map<Integer, byte[]> clientExtensions, int greaseGroup) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        // Safari really does offer rsa_pss_rsae_sha384 twice.
        addSignatureAlgorithmsExtension(clientExtensions,
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        addSupportedGroupsExtension(clientExtensions, greaseGroup, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions,
                new short[] { PskKeyExchangeMode.psk_dhe_ke });
        // zlib, where Chrome asks for brotli.
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions,
                new int[] { CertificateCompressionAlgorithm.zlib });
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        int supportedGroupGrease = randomGrease();
        addSharedExtensions(clientExtensions, supportedGroupGrease);
        randomSupportedVersionsExtension(clientExtensions);

        Vector<KeyShareEntry> keyShareEntries = new Vector<>(1);
        keyShareEntries.add(0, new KeyShareEntry(supportedGroupGrease, new byte[1]));
        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        return new ExtensionOrder("0-23-65281-10-11-16-5-13-18-51-45-43-27", true);
    }


    /**
     * The ClientHello Safari sends over QUIC, from a Wireshark capture of Safari 26.6.2 against
     * {@code quic.tools.scrapfly.io/api/fp/quic}; iOS 26.6 sends the same one.
     * <p>
     * It is the TCP ClientHello with the TLS 1.2 era extensions dropped - no "extended_master_secret",
     * no "renegotiation_info", no "ec_point_formats" - and "quic_transport_parameters" added before
     * "compress_certificate". Everything else is the same, down to offering rsa_pss_rsae_sha384
     * twice, which is what makes the two profiles recognizably one browser.
     * <p>
     * Unlike Chrome's QUIC ClientHello, which greases nothing, this one greases in five places: a
     * cipher suite, an extension at each end, a named group and the key share that goes with it, and
     * a supported version. That asymmetry is worth knowing about, because it is Chrome that is the
     * odd one here - its TCP ClientHello greases and its QUIC one does not.
     */
    @Override
    public QuicClientHello getQuicClientHello() {
        return new QuicClientHello() {

            /**
             * Drawn once for this connection, because Safari uses the same value for the named group
             * and for the key share entry that goes with it.
             */
            private final int greaseGroup = randomGrease();

            @Override
            public int[] getCipherSuites() {
                return new int[] {
                        randomGrease(),
                        CipherSuite.TLS_AES_256_GCM_SHA384,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_AES_128_GCM_SHA256
                };
            }

            @Override
            public int[] getKeyShareGroups() {
                return new int[] { greaseGroup, NamedGroup.X25519MLKEM768, NamedGroup.x25519 };
            }

            @Override
            public ExtensionOrder onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
                /*
                 * BouncyCastle puts a "status_request" in the TCP ClientHello of its own accord; over
                 * QUIC nothing does, so Safari's is written out here. OCSP, an empty responder id
                 * list and no request extensions, which is all it asks for.
                 */
                clientExtensions.put(ExtensionType.status_request, new byte[] { 1, 0, 0, 0, 0 });
                addSharedExtensions(clientExtensions, greaseGroup);
                /*
                 * A GREASE version and TLS 1.3, and not the TLS 1.2 the shared helper also offers:
                 * over QUIC there is no TLS 1.2 to fall back to, RFC 9001 section 4.2 allows only
                 * 1.3, and a server answers the offer with a "protocol_version" alert. The capture
                 * shows the same two.
                 */
                int greaseVersion = randomGrease();
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[] {
                        ProtocolVersion.get(greaseVersion >> 8, greaseVersion & 0xff),
                        ProtocolVersion.TLSv13
                });
                /*
                 * One order for both handshakes. A fresh ClientHello has neither "early_data" nor
                 * "pre_shared_key" and the two names are simply skipped; a resumed one has both, and
                 * a capture of Safari refreshing a page puts early_data between psk_key_exchange_modes
                 * and supported_versions. The pre_shared_key is named last here and ends up last on
                 * the wire, after the trailing GREASE - RFC 8446 section 4.2.11 requires it of every
                 * ClientHello and the capture agrees; the spec pins it there.
                 */
                return new ExtensionOrder("0-10-16-5-13-18-51-45-42-43-57-27-41", true);
            }
        };
    }

    /**
     * Both of Safari's ClientHellos are captured - docs/captures/safari-26-quic.json and
     * safari-26-quic-resumed.json - so a resumed handshake can be described rather than guessed at.
     */
    @Override
    public boolean isQuicSessionResumptionSupported() {
        return true;
    }

    /**
     * The QUIC layer of the same capture. Six parameters and no more: no max_idle_timeout, no
     * max_udp_payload_size, no initial_max_streams_bidi, no ack_delay_exponent, no max_ack_delay, no
     * disable_active_migration, no GREASE and no version_information - a much shorter list than
     * Chrome's, and the shortness is itself the fingerprint.
     * <p>
     * One thing here is not reproduced. Safari sends these parameters in a rotated order: three
     * captures give 4,5,6,7,9,14,15 then 6,7,9,14,15,4,5 then 5,6,7,9,14,15,4 - the same cycle
     * started at a different point each time, which three times running is not chance. kwik writes
     * them in its own fixed order, and rotating them would mean reaching into how the transport
     * parameters extension is serialized. Recorded rather than guessed at or quietly ignored.
     * <p>
     * The Initial datagram is padded to 1200, the smallest RFC 9000 section 14.1 allows, where Chrome
     * pads to 1250. The fingerprint endpoint reports 1250 for both and is simply wrong about it; the
     * capture shows Safari's Initials at 1200 bytes. And the ClientHello goes out as one CRYPTO frame
     * per packet in order, so there is no chaos protection here - that is Chrome's alone.
     */
    @Override
    public QuicTransport getQuicTransport() {
        return QuicTransport.newBuilder()
                .destinationConnectionIdLength(8)
                .sourceConnectionIdLength(0)
                .initialDatagramSize(1200)
                .initialMaxData(16777216L)
                .initialMaxStreamDataBidirectional(2097152L)
                .initialMaxStreamDataUnidirectional(2097152L)
                .initialMaxStreamsUnidirectional(8)
                .activeConnectionIdLimit(64)
                .omit(QuicTransport.MAX_IDLE_TIMEOUT, QuicTransport.MAX_UDP_PAYLOAD_SIZE,
                        QuicTransport.INITIAL_MAX_STREAMS_BIDI, QuicTransport.ACK_DELAY_EXPONENT,
                        QuicTransport.MAX_ACK_DELAY, QuicTransport.DISABLE_ACTIVE_MIGRATION)
                .build();
    }

    /**
     * The HTTP/3 SETTINGS of the same capture: {@code 1:16383, 7:100} and a GREASE one, in that
     * order. Safari sends neither MAX_FIELD_SECTION_SIZE nor H3_DATAGRAM.
     * <p>
     * Both of these are promises the QPACK decoder underneath now keeps: a 16383 byte dynamic table
     * and a hundred streams allowed to block on it.
     */
    @Override
    public Map<Long, Long> getHttp3Settings() {
        Map<Long, Long> settings = new LinkedHashMap<>();
        settings.put(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 16383L);
        settings.put(Http3Settings.QPACK_BLOCKED_STREAMS, 100L);
        settings.put(Http3Settings.randomGrease(), (long) ThreadLocalRandom.current().nextInt(Integer.MAX_VALUE));
        return settings;
    }
}
