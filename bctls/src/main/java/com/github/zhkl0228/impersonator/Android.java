package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
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
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.Locale;
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
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        MacChrome.configChromeHttp2Settings(http2Connection);
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Sec-Fetch-Dest", "empty");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
    }

    private static void addApplicationSettingsExtension(Map<Integer, byte[]> clientExtensions) throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(16)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeShort(3);
            byte[] bytes = "h2".getBytes();
            dataOutput.writeByte(bytes.length);
            dataOutput.write(bytes);
            clientExtensions.put(0x4469, baos.toByteArray());
        }
    }

    @Override
    protected ExtensionOrder onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
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
        int supportedGroupGrease = randomGrease();
        addSupportedGroupsExtension(clientExtensions, supportedGroupGrease, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.brotli});
        clientExtensions.put(ExtensionType.encrypted_client_hello, Hex.decodeStrict("000001000138002054b1fcc8868629a9ec88d5b183f9e26917229f69035b4ac94e833dd431bc4a5e00902f73c090762306de7f3fe1bd8d6ea5e4a577715d7385301e7340140f2970e5e58ad4c6584456035ec1f079afbbba4ad0e1292e3b7dfc3f9305a863e4b152c6880def239a16843469fbc2a46846b2a2007b6d97a4d5f897f5d6df2b33b31e3f306ac3f4fe5d229dfffe3dcf209c710430d8f4bb97b86be8ef1437425a3c693dfed5afa5c7ad0b84965060bd10d805cee0"));
        addApplicationSettingsExtension(clientExtensions);
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(supportedGroupGrease, new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        return new ExtensionOrder(null, true);
    }
}
