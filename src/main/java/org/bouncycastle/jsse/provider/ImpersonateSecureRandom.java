package org.bouncycastle.jsse.provider;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

public abstract class ImpersonateSecureRandom extends SecureRandom implements Impersonator {

    private static final Logger log = LoggerFactory.getLogger(ImpersonateSecureRandom.class);

    public static SecureRandom chrome() {
        // Ja3: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0
        // scrapfly_fp => version:772|ch_ciphers:GREASE-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53|ch_extensions:GREASE-0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281-GREASE|groups:GREASE-25497-29-23-24|points:0|compression:0|supported_versions:GREASE-772-771|supported_protocols:h2-http11|key_shares:GREASE-25497-29|psk:1|signature_algs:1027-2052-1025-1283-2053-1281-2054-1537|early_data:0|
        return new ImpersonateSecureRandom("0x9a9a-4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53") {
            @Override
            public void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException {
                clientExtensions.put(ExtensionType.renegotiation_info, TlsUtils.encodeOpaque8(TlsUtils.EMPTY_BYTES));
            }
            @Override
            public void onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException {
                TlsExtensionsUtils.addSupportedVersionsExtensionClient(clientExtensions, new ProtocolVersion[] {
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
                Vector<Integer> supportedGroups = new Vector<>();
                final int X25519Kyber768Draft00 = 0x6399;
                supportedGroups.add(0xcaca);
                supportedGroups.add(X25519Kyber768Draft00);
                supportedGroups.add(NamedGroup.x25519);
                supportedGroups.add(NamedGroup.secp256r1);
                supportedGroups.add(NamedGroup.secp384r1);
                TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
                Vector<SignatureAndHashAlgorithm> supportedSignatureAlgorithms = new Vector<>();
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp256r1_sha256));
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha256);
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha256));
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.create(SignatureScheme.ecdsa_secp384r1_sha384));
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha384);
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha384));
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.rsa_pss_rsae_sha512);
                supportedSignatureAlgorithms.add(SignatureAndHashAlgorithm.create(SignatureScheme.rsa_pkcs1_sha512));
                TlsExtensionsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
                Vector<KeyShareEntry> keyShareEntries = TlsExtensionsUtils.getKeyShareClientHello(clientExtensions);
                if (keyShareEntries != null) {
                    keyShareEntries.add(0, new KeyShareEntry(X25519Kyber768Draft00, new byte[1]));
                    keyShareEntries.add(0, new KeyShareEntry(0xcaca, new byte[1]));
                    TlsExtensionsUtils.addKeyShareClientHello(clientExtensions, keyShareEntries);
                }
                Map<Integer, byte[]> copy = new HashMap<>(clientExtensions);
                clientExtensions.clear();
                List<Integer> keys = new ArrayList<>(copy.keySet());
                Collections.shuffle(keys);
                clientExtensions.put(0x1a1a, TlsUtils.EMPTY_BYTES);
                for(Integer key : keys) {
                    byte[] data = copy.remove(key);
                    clientExtensions.put(key, data);
                }
                clientExtensions.put(0xcaca, TlsUtils.EMPTY_BYTES);
            }
        };
    }

    private final int[] cipherSuites;
    final String[] cipherSuitesNames;

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    private ImpersonateSecureRandom(String cipherSuites) {
        String[] tokens = cipherSuites.split("-");
        this.cipherSuites = new int[tokens.length];
        this.cipherSuitesNames = new String[tokens.length];
        for (int i = 0; i < tokens.length; i++) {
            String token = tokens[i];
            if (token.startsWith("0x")) {
                this.cipherSuites[i] = Integer.parseInt(token.substring(2), 16);
                continue;
            }
            int cipherSuite = Integer.parseInt(token);
            String name = ProvSSLContextSpi.getCipherSuiteName(cipherSuite);
            if (name == null) {
                throw new IllegalArgumentException("cipherSuites=" + cipherSuites + ", cipherSuite=" + cipherSuite);
            }
            log.debug("cipherSuite={}, name={}", cipherSuite, name);
            this.cipherSuites[i] = cipherSuite;
            this.cipherSuitesNames[i] = name;
        }
    }

}
