package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.internal.http2.Settings;
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
import java.util.Map;
import java.util.Vector;

/**
 * Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15
 * v17.5 (18618.2.12.111.5, 18618)
 */
class MacSafari17 extends ImpersonatorFactory {

    private enum Type {
        MacSafari,
        iOS
    }

    static ImpersonatorApi newMacSafari() {
        return new MacSafari17(Type.MacSafari, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15");
    }

    static ImpersonatorApi newIOS() {
        return new MacSafari17(Type.iOS, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.108 Mobile/15E148 Safari/604.1");
    }

    private final Type type;

    private MacSafari17(Type type, String userAgent) {
        super("0x" + Integer.toHexString(randomGrease()) + "-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10",
                userAgent);
        this.type = type;
    }

    @Override
    protected void onHttp2ConnectionInit(Http2Connection http2Connection) {
        switch (type) {
            case MacSafari: {
                http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 4194304);
                http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
                http2Connection.setWindowSizeIncrement(10485760L);
                http2Connection.setHeaderOrder("m,s,p,a");
                break;
            }
            case iOS: {
                http2Connection.setSetting(Settings.ENABLE_PUSH, 0);
                http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 2097152);
                http2Connection.setSetting(Settings.MAX_CONCURRENT_STREAMS, 100);
                http2Connection.setWindowSizeIncrement(10485760L);
                http2Connection.setHeaderOrder("m,s,p,a");
                break;
            }
            default:
                throw new IllegalStateException("Unsupported type: " + type);
        }
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        super.onSendClientHelloMessage(clientExtensions);
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        addSupportedGroupsExtension(clientExtensions, randomGrease(), NamedGroup.x25519, NamedGroup.secp256r1,
                NamedGroup.secp384r1, NamedGroup.secp521r1);
        randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12, ProtocolVersion.TLSv11, ProtocolVersion.TLSv10);
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(randomGrease(), new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        TlsExtensionsUtils.addPaddingExtension(clientExtensions, 0);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.zlib});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        randomExtension(clientExtensions, "0-23-65281-10-11-16-5-13-18-51-45-43-27-21", true);
    }

}
