package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import org.bouncycastle.tls.TlsEchRejectedException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
     * RFC 9849 6.1.7 has the client finish the handshake and only then abort with "ech_required",
     * before any application data. That matters beyond conformance: a browser sends its Finished
     * too, so a client that walked away at CertificateVerify would be telling every server that
     * rejects ECH that it is not the browser it claims to be.
     * <p>
     * Measured against this server: four records go out when the Finished is sent, three when the
     * handshake is abandoned at CertificateVerify, the difference being one 58 byte record.
     * <p>
     * The listener must stay silent, though. The abort stops short of completeHandshake precisely
     * so that nothing announces success for a connection that is about to die - the event would
     * arrive on its own thread, racing the exception, carrying a session whose certificate belongs
     * to the public_name rather than to the host the caller asked for.
     */
    public void testTheFinishedIsSentButNoCompletionIsAnnounced() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance().getEchConfigList(HOST);
        assertNotNull(HOST + " should publish an ECHConfigList", echConfigList);
        final byte[] corrupted = corruptPublicKey(echConfigList);

        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        api.setEchConfigProvider(host -> corrupted);
        SSLContext context = api.newSSLContext(null, null);

        final CountDownLatch completed = new CountDownLatch(1);
        CountingSocket plain = new CountingSocket(HOST, 443);
        try (Socket owned = plain;
             SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket(plain, HOST, 443, true)) {
            socket.addHandshakeCompletedListener(event -> completed.countDown());

            try {
                socket.startHandshake();
                fail("expected the server to reject ECH");
            } catch (TlsEchRejectedException expected) {
                assertTrue("the Finished must go out before the rejection; three records means it did not, got "
                        + plain.records, plain.records > 3);
                assertFalse("a connection that is being abandoned must not be announced as complete",
                        completed.await(2, TimeUnit.SECONDS));
            }
        }
    }

    /** Counts the records written to the wire, which is how the Finished above is seen from here. */
    private static class CountingSocket extends Socket {
        int records;
        int bytes;

        CountingSocket(String host, int port) throws IOException {
            super(host, port);
        }

        @Override
        public java.io.OutputStream getOutputStream() throws IOException {
            final java.io.OutputStream out = super.getOutputStream();
            return new java.io.OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    out.write(b);
                }

                @Override
                public void write(byte[] b, int off, int len) throws IOException {
                    records++;
                    bytes += len;
                    out.write(b, off, len);
                }

                @Override
                public void flush() throws IOException {
                    out.flush();
                }
            };
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
