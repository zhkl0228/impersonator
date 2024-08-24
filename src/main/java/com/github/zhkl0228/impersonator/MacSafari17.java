package com.github.zhkl0228.impersonator;

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
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

/**
 * v17.5 (18618.2.12.111.5, 18618)
 */
class MacSafari17 extends ImpersonatorFactory {

    MacSafari17() {
        super("0x8a8a-4865-4866-4867-49196-49195-52393-49200-49199-52392-49162-49161-49172-49171-157-156-53-47-49160-49170-10");
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
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
        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[]{
                ProtocolVersion.get(0xda, 0xda),
                ProtocolVersion.TLSv13, ProtocolVersion.TLSv12, ProtocolVersion.TLSv11, ProtocolVersion.TLSv10
        });
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(0x6a6a, new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        TlsExtensionsUtils.addPaddingExtension(clientExtensions, 0);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.zlib});
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        {
            Vector<Integer> supportedGroups = new Vector<>();
            supportedGroups.add(0x6a6a);
            supportedGroups.add(NamedGroup.x25519);
            supportedGroups.add(NamedGroup.secp256r1);
            supportedGroups.add(NamedGroup.secp384r1);
            supportedGroups.add(NamedGroup.secp521r1);
            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
        }
        {
            Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
            clientExtensions.clear();
            clientExtensions.put(0x6a6a, TlsUtils.EMPTY_BYTES);
            sortExtensions(clientExtensions, copy, "0-23-65281-10-11-16-5-13-18-51-45-43-27-21");
            clientExtensions.put(0x1a1a, TlsUtils.EMPTY_BYTES);
        }
    }

}
