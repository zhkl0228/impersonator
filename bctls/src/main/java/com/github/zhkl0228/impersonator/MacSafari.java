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

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

/**
 * macOS Safari v26.6.2 and iOS Safari v26.6. Captures of both are byte identical - same ClientHello,
 * same HTTP/2 settings, same header order - so the only thing that distinguishes them is the user
 * agent. Neither offers Encrypted Client Hello.
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
        http2Connection.setHeaderOrder("m,s,a,p");
    }

    @Override
    public int[] getKeyShareGroups() {
        return new int[] { NamedGroup.X25519MLKEM768, NamedGroup.x25519 };
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        // Safari really does offer rsa_pss_rsae_sha384 twice.
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        int supportedGroupGrease = randomGrease();
        addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1);
        randomSupportedVersionsExtension(clientExtensions);

        Vector<KeyShareEntry> keyShareEntries = new Vector<>(1);
        keyShareEntries.add(0, new KeyShareEntry(supportedGroupGrease, new byte[1]));
        TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.zlib});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        return new ExtensionOrder("0-23-65281-10-11-16-5-13-18-51-45-43-27", true);
    }

}
