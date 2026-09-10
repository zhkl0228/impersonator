package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.*;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * v155.0. Its QUIC fingerprint comes from a Wireshark capture cross-checked against the endpoint's
 * report of the same connections; see docs/captures/firefox-155-quic*.
 */
class MacFirefox extends ImpersonatorFactory {

    MacFirefox() {
        super("4865-4867-4866-49195-49199-52393-52392-49196-49200-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:155.0) Gecko/20100101 Firefox/155.0",
                true);
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        // Insertion order is the order they go on the wire, so it follows Firefox's own.
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Accept-Encoding", "gzip, deflate, br, zstd");
        headers.put("Upgrade-Insecure-Requests", "1");
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Priority", "u=0, i");
        headers.put("TE", "trailers");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        http2Connection.setSetting(Settings.HEADER_TABLE_SIZE, 65536);
        http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 131072);
        http2Connection.setSetting(Settings.MAX_FRAME_SIZE, 16384);
        http2Connection.setWindowSizeIncrement(12517377L);
        http2Connection.setHeaderOrder(getPseudoHeaderOrder());
    }

    /**
     * ":method", ":path", ":authority", ":scheme" - asserted against a capture in MacFirefoxTest.
     * <p>
     * Set explicitly although it is also okhttp's own order, which is why this profile sent the right
     * one while saying nothing. Relying on that left the browser's order resting on a library default
     * that no test names and any upstream release could change.
     */
    @Override
    public String getPseudoHeaderOrder() {
        return "m,p,a,s";
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1 };
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp521r1_sha512),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        addDelegatedCredentialsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp521r1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1));
        addSupportedGroupsExtension(clientExtensions, NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1,
                NamedGroup.secp521r1, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072);
        TlsExtensionsUtils.addRecordSizeLimitExtension(clientExtensions, 0x4001);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        clientExtensions.remove(ExtensionType.key_share);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{
                CertificateCompressionAlgorithm.zlib,
                CertificateCompressionAlgorithm.brotli,
                CertificateCompressionAlgorithm.zstd
        });
        return new ExtensionOrder("0-23-65281-10-11-35-16-5-34-41-18-51-43-13-45-28-27-65037", false);
    }


    /**
     * The ClientHello Firefox sends over QUIC, which is not its TCP one with the TLS 1.2 parts
     * removed - Safari's is, and Firefox's keeps "extended_master_secret" and "renegotiation_info"
     * that Safari drops. Three other differences from its own TCP ClientHello are worth naming
     * because they were all found by looking rather than assumed: the signature algorithms come in a
     * different order, with ecdsa_sha1 fourth instead of tenth; the named groups drop the two finite
     * field ones; and certificate compression asks for zlib and zstd where TCP asks for zlib, brotli
     * and zstd.
     * <p>
     * Nothing here is GREASEd. Chrome's QUIC ClientHello greases nothing either while its TCP one
     * does, and Safari's greases in five places - so this is a real axis of difference and not a
     * detail. Firefox does grease elsewhere: two of its HTTP/3 settings, one of its transport
     * parameters, and the other versions it lists in version_information.
     */
    @Override
    public QuicClientHello getQuicClientHello() {
        return new QuicClientHello() {

            @Override
            public int[] getCipherSuites() {
                return new int[] {
                        CipherSuite.TLS_AES_128_GCM_SHA256,
                        CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                        CipherSuite.TLS_AES_256_GCM_SHA384
                };
            }

            @Override
            public int[] getKeyShareGroups() {
                // Three, where Chrome and Safari offer two.
                return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1 };
            }

            @Override
            public ExtensionOrder onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions,
                        new ProtocolVersion[] { ProtocolVersion.TLSv13 });
                TlsExtensionsUtils.addRecordSizeLimitExtension(clientExtensions, 0x4001);
                clientExtensions.put(ExtensionType.extended_master_secret, TlsUtils.EMPTY_BYTES);
                // An empty renegotiated_connection, which is what a client that has never renegotiated sends.
                clientExtensions.put(ExtensionType.renegotiation_info, new byte[] { 0 });
                // OCSP, an empty responder id list and no request extensions.
                clientExtensions.put(ExtensionType.status_request, new byte[] { 1, 0, 0, 0, 0 });
                addSignatureAlgorithmsExtension(clientExtensions,
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp521r1_sha512),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1),
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                        SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                        SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
                addDelegatedCredentialsExtension(clientExtensions,
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp521r1_sha512),
                        SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1));
                addSupportedGroupsExtension(clientExtensions, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
                        NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1);
                TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions,
                        new short[] { PskKeyExchangeMode.psk_dhe_ke });
                TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[] {
                        CertificateCompressionAlgorithm.zlib,
                        CertificateCompressionAlgorithm.zstd
                });
                // A host that publishes an ECHConfig gets a real Encrypted Client Hello in this slot;
                // the capture is of one that did, and the endpoint reported ech_success.
                addGreaseEncryptedClientHelloExtension(clientExtensions);
                /*
                 * Firefox permutes its ClientHello extensions, so there is no order to hardcode.
                 * Four captured ClientHellos gave four different orders:
                 * <pre>
                 *   28,10,23,34,5,13,65281,16,51,27,45,43,0,     57,65037
                 *   65281,16,34,28,0,27,43,23,13,45,5,51,10,     57,65037
                 *   51,43,28,34,5,0,45,65281,13,23,10,27,16,     57,65037
                 *   5,10,23,0,51,27,34,13,28,65281,45,42,16,43,  57,65037,41
                 * </pre>
                 * Every extension moves except the last two, and the odds of those two landing there
                 * four times running are about one in ten thousand, so they are pinned rather than
                 * lucky. That is NSS: it permutes the extensions it builds from its own table, then
                 * the QUIC transport parameters go on as a custom extension and the Encrypted Client
                 * Hello last of all, because it has to cover everything before it.
                 * <p>
                 * The fourth line is a resumed handshake, and it is the reason early_data is not
                 * pinned either - it came up twelfth of seventeen, inside the permuted block. That
                 * rests on one capture rather than four. pre_shared_key is last by RFC 8446 section
                 * 4.2.11 and QuicClientHelloSpec puts it there whatever this asks for.
                 */
                return new ExtensionOrder(ImpersonatorFactory.SHUFFLE_THE_REST + "-57-65037", false);
            }
        };
    }

    /**
     * Both of Firefox's ClientHellos are captured - docs/captures/firefox-155-quic.json and
     * firefox-155-quic-resumed.json - so a resumed handshake can be described rather than guessed at.
     * The resumed one adds early_data and pre_shared_key to the same fifteen extensions, and the
     * endpoint reported 0-rtt for it where it reported none for Safari's.
     */
    @Override
    public boolean isQuicSessionResumptionSupported() {
        return true;
    }

    /**
     * The QUIC layer of the same captures. Fourteen parameters, the longest list of the three
     * browsers here, and two of them are things neither of the others sends: a version_information
     * naming two GREASE versions beside the real one, and an empty parameter 0x1d that Wireshark does
     * not recognize and this does not pretend to - it is reproduced as the bytes it is.
     * <p>
     * The Destination Connection ID length is drawn per connection rather than fixed. Four captured
     * connections gave 8, 13, 14 and 19, which is neqo's ConnectionId::generate_initial:
     * <pre>
     *   // Apply a wee bit of greasing here in picking a length between 8 and 20 bytes long.
     *   let v = random::&lt;1&gt;()[0];
     *   // Bias selection toward picking 8 (&gt;50% of the time).
     *   let len: usize = max(8, 5 + (v &amp; (v &gt;&gt; 4))).into();
     * </pre>
     * A fixed 8 would be right more than half the time and wrong the rest, which is worse than being
     * right every time: the length would never vary, and never varying is itself the tell.
     */
    @Override
    public QuicTransport getQuicTransport() {
        return QuicTransport.newBuilder()
                .destinationConnectionIdLength(MacFirefox::initialConnectionIdLength)
                .sourceConnectionIdLength(3)
                .sniSlicing()
                .initialDatagramSize(1252)
                .maxIdleTimeoutMillis(30000L)
                .initialMaxData(25165824L)
                .initialMaxStreamDataBidirectional(12582912L)
                .initialMaxStreamDataBidirectionalRemote(1048576L)
                .initialMaxStreamDataUnidirectional(1048576L)
                .initialMaxStreamsBidirectional(100)
                .initialMaxStreamsUnidirectional(100)
                .maxAckDelayMillis(20)
                .activeConnectionIdLimit(8)
                .maxDatagramFrameSize(65535)
                .availableVersions(QuicTransport.greaseVersion(), QuicTransport.greaseVersion())
                // Empty, and unrecognized: reproduced rather than explained.
                .parameter(0x1d, new byte[0])
                .greaseParameter()
                .omit(QuicTransport.MAX_UDP_PAYLOAD_SIZE, QuicTransport.ACK_DELAY_EXPONENT,
                        QuicTransport.DISABLE_ACTIVE_MIGRATION)
                .build();
    }

    /** neqo's ConnectionId::generate_initial; see {@link #getQuicTransport()}. */
    private static int initialConnectionIdLength() {
        int v = ThreadLocalRandom.current().nextInt(256);
        return Math.max(8, 5 + (v & (v >> 4)));
    }

    /**
     * The HTTP/3 SETTINGS of the same capture: {@code 1:65536, 7:20, 8:1, 51:1} and two GREASE ones.
     * Firefox is the only one of the three that sends SETTINGS_ENABLE_CONNECT_PROTOCOL, and the only
     * one that greases twice.
     */
    @Override
    public Map<Long, Long> getHttp3Settings() {
        Map<Long, Long> settings = new LinkedHashMap<>();
        settings.put(Http3Settings.QPACK_MAX_TABLE_CAPACITY, 65536L);
        settings.put(Http3Settings.QPACK_BLOCKED_STREAMS, 20L);
        settings.put(Http3Settings.ENABLE_CONNECT_PROTOCOL, 1L);
        settings.put(Http3Settings.H3_DATAGRAM, 1L);
        long grease = Http3Settings.randomGrease();
        settings.put(grease, 1L);
        long second = Http3Settings.randomGrease();
        settings.put(second == grease ? second + 0x1fL : second, 0L);
        return settings;
    }
}
