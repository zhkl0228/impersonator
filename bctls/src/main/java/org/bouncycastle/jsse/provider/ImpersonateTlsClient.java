package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsFatalAlert;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

class ImpersonateTlsClient extends ProvTlsClient {

    private final int[] cipherSuites;
    private final Impersonator impersonator;

    ImpersonateTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters, int[] cipherSuites,
                         Impersonator impersonator) {
        super(manager, sslParameters);
        this.cipherSuites = cipherSuites;
        this.impersonator = impersonator;
    }

    @Override
    public int[] getCipherSuites() {
        return cipherSuites;
    }

    /**
     * The ECHConfigList is looked up by the same name that would otherwise be sent as a plaintext
     * SNI, so that the caller's provider is keyed on the host it knows about.
     */
    @Override
    public byte[] getEchConfigList() {
        return impersonator.getEchConfigList(JsseUtils.stripTrailingDot(manager.getPeerHostSNI()));
    }

    /**
     * The chain has already been through the trust manager, so what is left is the name match. It
     * is done here rather than through {@code endpointIdentificationAlgorithm} because that setting
     * would check the real host, which is exactly the name the ClientHelloOuter did not carry.
     * <p>
     * Wildcards are matched the way {@link ProvX509TrustManager#checkEndpointID} matches them for
     * HTTPS: leftmost label only, per RFC 9525 section 6.3.
     */
    @Override
    public void checkEchPublicName(String publicName) throws IOException {
        Certificate peerCertificate = context.getSecurityParametersHandshake().getPeerCertificate();
        if (null == peerCertificate || peerCertificate.isEmpty()) {
            throw new TlsFatalAlert(AlertDescription.internal_error,
                    "Encrypted Client Hello was rejected and the public_name " + publicName
                            + " has to be authenticated, but no server certificate was received.");
        }

        X509Certificate[] chain = JsseUtils.getX509CertificateChain(getCrypto(), peerCertificate);
        try {
            HostnameUtil.checkHostname(publicName, chain[0], false);
        } catch (CertificateException e) {
            throw new TlsFatalAlert(AlertDescription.bad_certificate,
                    "Encrypted Client Hello was rejected and the certificate does not identify the ECHConfig's"
                            + " public_name " + publicName + ", so its retry_configs cannot be trusted.", e);
        }
    }
}
