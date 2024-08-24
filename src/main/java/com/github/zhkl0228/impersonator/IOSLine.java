package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ExtensionType;
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

class IOSLine extends ImpersonatorFactory {

    IOSLine() {
        super("4865-4866-4867-49195-49199-49196-49200-52393-52392-49162-49172-49161-49171-156-157-47-53");
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[]{
                ProtocolVersion.TLSv13, ProtocolVersion.TLSv12
        });
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        clientExtensions.remove(ExtensionType.status_request);
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        addSupportedGroupsExtension(clientExtensions, NamedGroup.x25519,
                NamedGroup.secp256r1, NamedGroup.secp384r1);
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512),
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha1));
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        TlsExtensionsUtils.addPaddingExtension(clientExtensions, 0);
        {
            Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
            clientExtensions.clear();
            sortExtensions(clientExtensions, copy, "0-23-65281-10-11-35-16-13-51-45-43-21");
        }
    }
}
