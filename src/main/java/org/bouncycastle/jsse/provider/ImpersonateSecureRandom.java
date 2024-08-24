package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.CertificateCompressionAlgorithm;
import org.bouncycastle.tls.ExtensionType;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.PskKeyExchangeMode;
import org.bouncycastle.tls.TlsExtensionsUtils;
import org.bouncycastle.tls.TlsUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Hashtable;
import java.util.Vector;

public abstract class ImpersonateSecureRandom extends SecureRandom implements Impersonator {

    private static final Logger log = LoggerFactory.getLogger(ImpersonateSecureRandom.class);

    public static SecureRandom chrome() {
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,25497-29-23-24,0
        // 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17513-65037-65281,29-23-24,0
        return new ImpersonateSecureRandom("4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53") {
            @Override
            public void onEstablishSession(Hashtable clientExtensions) throws IOException {
                clientExtensions.put(ExtensionType.renegotiation_info, TlsUtils.encodeOpaque8(TlsUtils.EMPTY_BYTES));
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
                Vector supportedGroups = new Vector();
                final int X25519Kyber768Draft00 = 0x6399;
                supportedGroups.add(X25519Kyber768Draft00);
                supportedGroups.add(NamedGroup.x25519);
                supportedGroups.add(NamedGroup.secp256r1);
                supportedGroups.add(NamedGroup.secp384r1);
                TlsExtensionsUtils.addSupportedGroupsExtension(clientExtensions, supportedGroups);
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
            int cipherSuite = Integer.parseInt(tokens[i]);
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
