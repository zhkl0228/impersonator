package org.bouncycastle.jsse.provider;

import com.github.zhkl0228.impersonator.Impersonator;
import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.AlertLevel;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsServerCertificate;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

class ImpersonateTlsClient extends ProvTlsClient {

    private static final Logger LOG = Logger.getLogger(ImpersonateTlsClient.class.getName());

    private final int[] cipherSuites;
    private final Impersonator impersonator;
    private final RealityHandshake reality;

    ImpersonateTlsClient(ProvTlsManager manager, ProvSSLParameters sslParameters, int[] cipherSuites,
                         Impersonator impersonator, RealityHandshake reality) {
        super(manager, sslParameters);
        this.cipherSuites = cipherSuites;
        this.impersonator = impersonator;
        this.reality = reality;
    }

    /**
     * A REALITY server's certificate is a temporary one it signs with the key this connection's
     * ClientHello established, so it is judged by that and never by a chain - there is no issuer to
     * find and nothing for a trust manager to say. Everything else, the client credentials included,
     * stays with {@link ProvTlsClient}.
     */
    @Override
    public TlsAuthentication getAuthentication() throws IOException {
        final TlsAuthentication authentication = super.getAuthentication();
        if (reality == null) {
            return authentication;
        }
        return new TlsAuthentication() {
            @Override
            public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                Certificate certificate = serverCertificate.getCertificate();
                if (certificate == null || certificate.isEmpty()) {
                    throw new TlsFatalAlert(AlertDescription.bad_certificate,
                            "a REALITY server always sends its temporary certificate, and this one sent none");
                }
                reality.verifyServerCertificate(certificate.getCertificateAt(0));
            }

            @Override
            public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) throws IOException {
                return authentication.getClientCredentials(certificateRequest);
            }
        };
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
        byte[] echConfigList = impersonator.getEchConfigList(JsseUtils.stripTrailingDot(manager.getPeerHostSNI()));
        if (reality != null && echConfigList != null) {
            /*
             * Only a real ECH conflicts, which is why this asks for the config list rather than for
             * whether the profile supports ECH: REALITY authenticates the exact bytes of the ClientHello
             * it sends, and Encrypted Client Hello puts a different message on the wire than the one it
             * hashes. A profile that does ECH is otherwise perfectly usable here - with no provider, or
             * with one that has nothing for this server name, nothing is offered and nothing collides.
             *
             * The GREASE ECH is unaffected and still goes out: it is one extension in one ClientHello,
             * and a browser profile that stopped sending it would no longer look like the browser.
             */
            throw new IllegalStateException("this REALITY connection has an ECHConfigList to offer for "
                    + JsseUtils.stripTrailingDot(manager.getPeerHostSNI()) + ", and REALITY authenticates the"
                    + " exact ClientHello it sends; drop the ECH provider or the entry for that name");
        }
        return echConfigList;
    }

    /**
     * A rejected Encrypted Client Hello is not a failure report; it is how the server hands over the
     * retry_configs it wants next time, and a client built by {@code OkHttpClientFactory} acts on
     * them and goes back by itself. {@link ProvTlsClient} logs every fatal alert at INFO with the
     * cause's stack trace, which makes that recovery read like a crash, so this one alert drops to
     * FINE. Every other alert keeps the level ProvTlsClient chose, and the exception still carries
     * the whole story to whoever asked for the connection.
     */
    @Override
    public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
        if (AlertLevel.fatal == alertLevel && AlertDescription.ech_required == alertDescription) {
            if (LOG.isLoggable(Level.FINE)) {
                String msg = JsseUtils.getAlertRaisedLogMessage(clientID, alertLevel, alertDescription);
                LOG.log(Level.FINE, null == message ? msg : msg + ": " + message, cause);
            }
            return;
        }

        super.notifyAlertRaised(alertLevel, alertDescription, message, cause);
    }

    /**
     * The chain has already been through the trust manager, so what is left is the name match. It
     * is done here rather than through {@code endpointIdentificationAlgorithm} because that setting
     * would check the real host, which is exactly the name the ClientHelloOuter did not carry.
     * <p>
     * Wildcards are matched the way
     * {@link ProvX509TrustManager#checkEndpointID(String, X509Certificate, String)} matches them
     * for HTTPS: leftmost label only, per RFC 9525 section 6.3.
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
