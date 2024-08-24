package com.github.zhkl0228.impersonator;

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
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

/**
 * Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0
 * v129.0.2
 */
class MacFirefox129 extends ImpersonatorFactory {

    public MacFirefox129() {
        super("4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53");
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
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
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        TlsExtensionsUtils.addRecordSizeLimitExtension(clientExtensions, 0x4000);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        addDelegatedCredentialsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp521r1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_sha1));
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        final int encrypted_client_hello = 0xfe0d;
        clientExtensions.put(encrypted_client_hello, TlsUtils.EMPTY_BYTES);
        {
            Vector<Integer> supportedGroups = new Vector<>();
            supportedGroups.add(NamedGroup.x25519);
            supportedGroups.add(NamedGroup.secp256r1);
            supportedGroups.add(NamedGroup.secp384r1);
            supportedGroups.add(NamedGroup.secp521r1);
            supportedGroups.add(NamedGroup.ffdhe2048);
            supportedGroups.add(NamedGroup.ffdhe3072);
            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
        }
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            byte[] keyExchange = new byte[65];
            new SecureRandom().nextBytes(keyExchange);
            keyShareEntries.add(new KeyShareEntry(NamedGroup.secp256r1, keyExchange));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
        clientExtensions.clear();
        sortExtensions(clientExtensions, copy, "0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037");
    }

}
