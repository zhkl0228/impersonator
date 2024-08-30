package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Request;
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
 * v127.0.6533.120
 */
class Android extends ImpersonatorFactory {

    Android() {
        super("GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36");
    }

    @Override
    protected void onHttp2ConnectionInit(Http2Connection http2Connection) {
        MacChrome127.configChromeHttp2Settings(http2Connection);
    }

    @Override
    protected void onInterceptRequest(Request.Builder builder) {
        builder.header("Accept-Language", "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7");
        builder.header("Sec-Fetch-Dest", "empty");
        builder.header("Sec-Fetch-Mode", "navigate");
        builder.header("Sec-Fetch-Site", "none");
    }

    @Override
    protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512));
        addSupportedGroupsExtension(clientExtensions, randomGrease(), NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.brotli});
        clientExtensions.put(ExtensionType.encrypted_client_hello, TlsUtils.EMPTY_BYTES);
        MacChrome127.addApplicationSettingsExtension(clientExtensions);
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(randomGrease(), new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        MacChrome127.randomExtension(clientExtensions, null, true);
    }
}
