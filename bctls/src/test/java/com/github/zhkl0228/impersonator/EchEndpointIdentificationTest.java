package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.tls.TlsEchRejectedException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Socket;

/**
 * Drives the JSSE socket directly, the way a caller that is not okhttp does. okhttp leaves
 * endpoint identification off and verifies the host itself afterwards, so nothing else in these
 * tests exercises the check that runs inside the handshake.
 */
public class EchEndpointIdentificationTest extends TestCase {

    private static final String HOST = "crypto.cloudflare.com";

    /**
     * With endpoint identification on, a rejected Encrypted Client Hello used to be unreportable.
     * The check runs from handleServerCertificate, so it happens before the rejection is raised at
     * CertificateVerify, and it would hold the ClientHelloOuter's certificate, issued for the
     * ECHConfig's public_name, against the host the caller asked for. That fails, and the
     * certificate error takes the place of the rejection, so the retry_configs the server published
     * never reach anyone and there is nothing to recover from.
     * <p>
     * The connection now reports the public_name as the name it requested, which is what it did
     * request, so the check has something to match and the rejection survives.
     */
    public void testARejectionSurvivesEndpointIdentification() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance().getEchConfigList(HOST);
        assertNotNull(HOST + " should publish an ECHConfigList", echConfigList);
        final byte[] corrupted = corruptPublicKey(echConfigList);

        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        api.setEchConfigProvider(host -> corrupted);
        SSLContext context = api.newSSLContext(null, null);

        // The impersonating factory only wraps an already connected socket, as okhttp does.
        try (Socket plain = new Socket(HOST, 443);
             SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, HOST, 443, true)) {
            SSLParameters parameters = socket.getSSLParameters();
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
            socket.setSSLParameters(parameters);

            try {
                socket.startHandshake();
                fail("expected the server to reject ECH");
            } catch (TlsEchRejectedException e) {
                assertEquals("cloudflare-ech.com", e.getPublicName());
                assertNotNull("the server should publish retry_configs", e.getRetryConfigs());
            } catch (IOException e) {
                fail("the rejection was replaced by " + e);
            }
        }
    }

    /**
     * Flip a bit of the ECHConfig's public key, leaving the public_name alone so the
     * ClientHelloOuter still goes to a name Cloudflare serves. X25519 does not validate public keys,
     * so the seal succeeds and it is the server that cannot open it.
     */
    private static byte[] corruptPublicKey(byte[] echConfigList) {
        // list(2) version(2) length(2) config_id(1) kem_id(2) public_key length(2) then the key.
        byte[] corrupted = echConfigList.clone();
        corrupted[2 + 4 + 1 + 2 + 2] ^= 0x01;
        return corrupted;
    }
}
