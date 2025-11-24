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
 * v142.0.7444.162
 */
class MacChrome extends ImpersonatorFactory {

    MacChrome() {
        super("GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36");
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Cache-Control", "max-age=0");
        headers.put("Sec-Ch-Ua", "\"Not)A;Brand\";v=\"99\", \"Google Chrome\";v=\"127\", \"Chromium\";v=\"127\"");
        headers.put("Sec-Ch-Ua-Mobile", "?0");
        headers.put("Sec-Ch-Ua-Platform", "\"macOS\"");
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Upgrade-Insecure-Requests", "1");
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
        randomSupportedVersionsExtension(clientExtensions, ProtocolVersion.TLSv13, ProtocolVersion.TLSv12);
        final int supportedGroupGrease = randomGrease();
        addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.X25519MLKEM768, NamedGroup.x25519,
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
        {
            Vector<KeyShareEntry> keyShareEntries = new Vector<>(1);
            keyShareEntries.add(new KeyShareEntry(ImpersonatorFactory.randomGrease(), new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        clientExtensions.put(ExtensionType.encrypted_client_hello, Hex.decodeStrict("000001000138002054b1fcc8868629a9ec88d5b183f9e26917229f69035b4ac94e833dd431bc4a5e00902f73c090762306de7f3fe1bd8d6ea5e4a577715d7385301e7340140f2970e5e58ad4c6584456035ec1f079afbbba4ad0e1292e3b7dfc3f9305a863e4b152c6880def239a16843469fbc2a46846b2a2007b6d97a4d5f897f5d6df2b33b31e3f306ac3f4fe5d229dfffe3dcf209c710430d8f4bb97b86be8ef1437425a3c693dfed5afa5c7ad0b84965060bd10d805cee0"));
        return new ExtensionOrder(null, true);
    }
}
