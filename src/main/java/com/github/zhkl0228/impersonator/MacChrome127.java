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

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

/**
 * v127.0.6533.120
 */
class MacChrome127 extends ImpersonatorFactory {

    MacChrome127() {
        super("0x9a9a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53");
    }

    @Override
    public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
        TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[]{
                ProtocolVersion.get(0x4a, 0x4a),
                ProtocolVersion.TLSv13, ProtocolVersion.TLSv12
        });
        clientExtensions.remove(ExtensionType.status_request_v2);
        clientExtensions.remove(ExtensionType.encrypt_then_mac);
        clientExtensions.put(ExtensionType.signed_certificate_timestamp, TlsUtils.EMPTY_BYTES);
        TlsExtensionsUtils.addCompressCertificateExtension(clientExtensions, new int[]{CertificateCompressionAlgorithm.brotli});
        clientExtensions.put(ExtensionType.session_ticket, TlsUtils.EMPTY_BYTES);
        TlsExtensionsUtils.addPSKKeyExchangeModesExtension(clientExtensions, new short[]{PskKeyExchangeMode.psk_dhe_ke});
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(16)) {
            DataOutput dataOutput = new DataOutputStream(baos);
            dataOutput.writeShort(3);
            byte[] bytes = "h2".getBytes();
            dataOutput.writeByte(bytes.length);
            dataOutput.write(bytes);
            final int application_settings = 0x4469;
            clientExtensions.put(application_settings, baos.toByteArray());
        }
        final int encrypted_client_hello = 0xfe0d;
        clientExtensions.put(encrypted_client_hello, TlsUtils.EMPTY_BYTES);
        final int X25519Kyber768Draft00 = 0x6399;
        {
            Vector<Integer> supportedGroups = new Vector<>();
            supportedGroups.add(0xcaca);
            supportedGroups.add(X25519Kyber768Draft00);
            supportedGroups.add(NamedGroup.x25519);
            supportedGroups.add(NamedGroup.secp256r1);
            supportedGroups.add(NamedGroup.secp384r1);
            TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
        }
        addSignatureAlgorithmsExtension(clientExtensions, SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256),
                SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384),
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512));
        Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
        if (keyShareEntries != null) {
            keyShareEntries.add(0, new KeyShareEntry(X25519Kyber768Draft00, new byte[1]));
            keyShareEntries.add(0, new KeyShareEntry(0xcaca, new byte[1]));
            TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
        }
        {
            Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
            clientExtensions.clear();
            List<Integer> keys = new ArrayList<>(copy.keySet());
            Collections.shuffle(keys);
            clientExtensions.put(0x1a1a, TlsUtils.EMPTY_BYTES);
            for (Integer key : keys) {
                byte[] data = copy.remove(key);
                clientExtensions.put(key, data);
            }
            clientExtensions.put(0xcaca, TlsUtils.EMPTY_BYTES);
        }
    }
}
