package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Settings;
import org.bouncycastle.tls.CertificateCompressionAlgorithm;
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
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

/**
 * v26.1 (20622.2.11.119.1)
 */
class MacSafari extends ImpersonatorFactory {

    private enum Type {
        MacSafari,
        iOS
    }

    static ImpersonatorApi newMacSafari() {
        return new MacSafari(Type.MacSafari, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15");
    }

    static ImpersonatorApi newIOS() {
        return new MacSafari(Type.iOS, "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Mobile/15E148 Safari/604.1\"");
    }

    private final Type type;

    private MacSafari(Type type, String userAgent) {
        super(
                type == Type.iOS ?
                        "GREASE-4866-4867-4865-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10" :
                        "GREASE-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10",
                userAgent);
        this.type = type;
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        switch (type) {
            case iOS:
            case MacSafari: {
                http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
                http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
                http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 2097152);
                http2Connection.setSetting(9, 1);
                http2Connection.setWindowSizeIncrement(10420225L);
                http2Connection.setHeaderOrder("m,s,a,p");
                break;
            }
            default:
                throw new IllegalStateException("Unsupported type: " + type);
        }
    }

    @Override
    protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
//                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        int supportedGroupGrease = randomGrease();
        if (type == Type.MacSafari) {
            addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.x25519, NamedGroup.secp256r1,
                    NamedGroup.secp384r1, NamedGroup.secp521r1);
            randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12, ProtocolVersion.TLSv11, ProtocolVersion.TLSv10);
        } else if (type == Type.iOS) {
            final int X25519MLKEM768 = 0x11ec;
            addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, X25519MLKEM768, NamedGroup.x25519, NamedGroup.secp256r1,
                    NamedGroup.secp384r1, NamedGroup.secp521r1);
            randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12);
        } else {
            throw new UnsupportedOperationException("Unsupported type: " + type);
        }
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(supportedGroupGrease, new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        if (type == Type.MacSafari) {
            TlsExtensionsUtils.addPaddingExtension(clientExtensions, 0);
        }
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.zlib});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        randomExtension(clientExtensions, "0-23-65281-10-11-16-5-13-18-51-45-43-27-21", true);
    }

}
