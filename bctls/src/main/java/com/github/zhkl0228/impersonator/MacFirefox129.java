package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.PriorityFrame;
import okhttp3.Settings;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;
import java.util.Vector;

/**
 * v129.0.2
 */
class MacFirefox129 extends ImpersonatorFactory {

    MacFirefox129() {
        super("4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0");
    }

    @Override
    public void fillRequestHeaders(Map<String, String> headers) {
        Locale locale = Locale.getDefault();
        headers.put("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8");
        headers.put("Accept-Language", String.format("%s,%s;q=0.5", locale.toString().replace('_', '-'), locale.getLanguage()));
        headers.put("Sec-Fetch-Dest", "document");
        headers.put("Sec-Fetch-Mode", "navigate");
        headers.put("Sec-Fetch-Site", "none");
        headers.put("Sec-Fetch-User", "?1");
        headers.put("Upgrade-Insecure-Requests", "1");
    }

    @Override
    public void onHttp2ConnectionInit(Http2Connection http2Connection) {
        http2Connection.removeSetting(Settings.INITIAL_WINDOW_SIZE);
        http2Connection.setSetting(Settings.HEADER_TABLE_SIZE, 65536);
        http2Connection.setSetting(Settings.INITIAL_WINDOW_SIZE, 131072);
        http2Connection.setSetting(Settings.MAX_FRAME_SIZE, 16384);
        http2Connection.setWindowSizeIncrement(12517377L);
        http2Connection.addPriorityFrame(new PriorityFrame(3, 0, 200));
        http2Connection.addPriorityFrame(new PriorityFrame(5, 0, 100));
        http2Connection.addPriorityFrame(new PriorityFrame(7, 0, 0));
        http2Connection.addPriorityFrame(new PriorityFrame(9, 7, 0));
        http2Connection.addPriorityFrame(new PriorityFrame(11, 3, 0));
        http2Connection.addPriorityFrame(new PriorityFrame(13, 0, 240));
    }

    @Override
    protected void onSendClientHelloMessageInternal(Map<Integer, byte[]> clientExtensions) throws IOException {
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
        addSupportedGroupsExtension(clientExtensions, NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1,
                NamedGroup.secp521r1, NamedGroup.ffdhe2048, NamedGroup.ffdhe3072);
        TlsExtensionsUtils.addRecordSizeLimitExtension(clientExtensions, 0x4000);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        clientExtensions.put(ExtensionType.encrypted_client_hello, Hex.decodeStrict("000001000138002054b1fcc8868629a9ec88d5b183f9e26917229f69035b4ac94e833dd431bc4a5e00902f73c090762306de7f3fe1bd8d6ea5e4a577715d7385301e7340140f2970e5e58ad4c6584456035ec1f079afbbba4ad0e1292e3b7dfc3f9305a863e4b152c6880def239a16843469fbc2a46846b2a2007b6d97a4d5f897f5d6df2b33b31e3f306ac3f4fe5d229dfffe3dcf209c710430d8f4bb97b86be8ef1437425a3c693dfed5afa5c7ad0b84965060bd10d805cee0"));
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            byte[] keyExchange = new byte[65];
            new SecureRandom().nextBytes(keyExchange);
            keyShareEntries.add(new KeyShareEntry(NamedGroup.secp256r1, keyExchange));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        randomExtension(clientExtensions, "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037", false);
    }

}
