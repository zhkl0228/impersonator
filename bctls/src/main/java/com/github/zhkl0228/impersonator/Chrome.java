package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.ExtensionType;
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
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

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
