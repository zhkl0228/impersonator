package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.*;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

/**
 * v152.0.7977.83
 */
class MacChrome extends ImpersonatorFactory {

    MacChrome() {
        super("GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
                true);
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        /*
         * Insertion order is the order they go on the wire. Chrome puts the client hints first and
         * the user agent only after Upgrade-Insecure-Requests, so it has to be taken out and put
         * back rather than left where the interceptor placed it.
         */
        String userAgent = headers.remove("User-Agent");
        headers.put("Sec-Ch-Ua", "\"Chromium\";v=\"152\", \"Not?A_Brand\";v=\"24\", \"Google Chrome\";v=\"152\"");
        headers.put("Sec-Ch-Ua-Mobile", "?0");
        headers.put("Sec-Ch-Ua-Platform", "\"macOS\"");
        headers.put("Upgrade-Insecure-Requests", "1");
        if (userAgent != null) {
            headers.put("User-Agent", userAgent);
        }
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        // services/network/sec_header_helpers.cc sets these as Site, Mode, User, Dest.
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Accept-Encoding", "gzip, deflate, br, zstd");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Priority", "u=0, i");
    }

    static void configChromeHttp2Settings(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        http2Connection.setSetting(Settings.HEADER_TABLE_SIZE, 65536);
        http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 6291456);
        http2Connection.setSetting(Settings.MAX_HEADER_LIST_SIZE, 262144);
        http2Connection.setWindowSizeIncrement(15663105L);
        http2Connection.setHeaderOrder("m,a,s,p");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        configChromeHttp2Settings(http2Connection);
    }

    /**
     * "trust_anchors", draft-ietf-tls-trust-anchor-ids. Not in {@link ExtensionType} because
     * BouncyCastle does not implement the draft.
     */
    private static final int EXT_trust_anchors = 51764;

    /**
     * The trust anchor ids Chrome advertises, captured from Chrome 152.0.7977.83. It is a list of
     * relative OIDs naming the CAs in Chrome's own root store, so it is fixed for a given Chrome
     * build rather than generated per connection - two captures from the same browser were byte
     * identical - and it has to be refreshed when the root store does.
     */
    private static final byte[] TRUST_ANCHORS = Hex.decodeStrict(
            "00b804d679090a08839a648c9b2d011208839a648c9b2d010808839a648c9b2d011304d679090d04d679090b"
                    + "0582df13020e04d679090508839a648c9b2d01090582df13020d0582df13020104d679090608839a648c9b"
                    + "2d010c08839a648c9b2d010704d679090c08839a648c9b2d010a04d679090104d679090408839a648c9b2d"
                    + "010d08839a648c9b2d010b0582df1302060582df1302130582df13021204d679090804d679090f0582df13"
                    + "020f0582df13021404d6790907");

    private static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(16)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeShort(3);
            byte[] bytes = "h2".getBytes();
            dataOutput.writeByte(bytes.length);
            dataOutput.write(bytes);
            clientExtensions.put(ExtensionType.application_settings, baos.toByteArray());
        }
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] {
                NamedGroup.X25519MLKEM768,
                NamedGroup.x25519
        };
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        randomSupportedVersionsExtension(clientExtensions);
        final int supportedGroupGrease = randomGrease();
        addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1);
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
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.brotli});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        addApplicationSettingsExtension(clientExtensions);
        clientExtensions.put(EXT_trust_anchors, TRUST_ANCHORS);
        {
            Vector<KeyShareEntry> keyShareEntries = new Vector<>(1);
            keyShareEntries.add(new KeyShareEntry(ImpersonatorFactory.randomGrease(), new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        return new ExtensionOrder(null, true);
    }
}
