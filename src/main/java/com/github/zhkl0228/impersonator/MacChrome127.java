package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.Request;
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

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Map;
import java.util.Vector;

/**
 * v127.0.6533.120
 */
class MacChrome127 extends ImpersonatorFactory {

    MacChrome127() {
        super("GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36");
    }

    @Override
    protected void onInterceptRequest(Request.Builder builder) {
        builder.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        builder.header("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8,zh-TW;q=0.7,mt;q=0.6");
        builder.header("Cache-Control", "max-age=0");
        builder.header("Cookie", "");
        builder.header("Sec-Ch-Ua", "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"");
        builder.header("Sec-Ch-Ua-Mobile", "?0");
        builder.header("Sec-Ch-Ua-Platform", "\"macOS\"");
        builder.header("Sec-Fetch-Dest", "document");
        builder.header("Sec-Fetch-Mode", "navigate");
        builder.header("Sec-Fetch-Site", "none");
        builder.header("Sec-Fetch-User", "?1");
        builder.header("Upgrade-Insecure-Requests", "1");
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
    protected void onHttp2ConnectionInit(Http2Connection http2Connection) {
        configChromeHttp2Settings(http2Connection);
    }

    static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
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
    protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12);
        final int X25519Kyber768Draft00 = 0x6399;
        addSupportedGroupsExtension(clientExtensions, randomGrease(), X25519Kyber768Draft00, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
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
        clientExtensions.put(ExtensionType.encrypted_client_hello, TlsUtils.EMPTY_BYTES);
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(X25519Kyber768Draft00, new byte[1]));
            keyShareEntries.add(0, new KeyShareEntry(randomGrease(), new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        randomExtension(clientExtensions, null, true);
    }
}
