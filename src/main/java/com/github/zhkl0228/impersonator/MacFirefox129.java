package com.github.zhkl0228.impersonator;

import okhttp3.Http2Connection;
import okhttp3.PriorityFrame;
import okhttp3.Request;
import okhttp3.internal.http2.Settings;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.KeyShareEntry;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Vector;

/**
 * Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0
 * v129.0.2
 */
class MacFirefox129 extends ImpersonatorFactory {

    MacFirefox129() {
        super("4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0");
    }

    @Override
    protected void onInterceptRequest(Request.Builder builder) {
        builder.header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8");
        builder.header("Accept-Language", "en-US,en;q=0.5");
        builder.header("Sec-Fetch-Dest", "document");
        builder.header("Sec-Fetch-Mode", "navigate");
        builder.header("Sec-Fetch-Site", "none");
        builder.header("Sec-Fetch-User", "?1");
        builder.header("Upgrade-Insecure-Requests", "1");
    }

    @Override
    protected void onHttp2ConnectionInit(Http2Connection http2Connection) {
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
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        super.onSendClientHelloMessage(clientExtensions);
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
        clientExtensions.put(ExtensionType.encrypted_client_hello, TlsUtils.EMPTY_BYTES);
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
