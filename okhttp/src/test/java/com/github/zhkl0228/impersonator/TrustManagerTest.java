package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;

import org.bouncycastle.tls.AlertDescription;
import org.bouncycastle.tls.TlsFatalAlert;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 * badssl.com serves these on purpose. The certificate carries the right host name in both cases, so
 * the hostname verifier is happy and the only thing standing between the client and the server is
 * whether the chain is checked at all.
 */
public class TrustManagerTest extends TestCase {

    private static final String SELF_SIGNED = "https://self-signed.badssl.com/";
    private static final String VALID = "https://sha256.badssl.com/";

    /** An unconfigured client gets the platform root store, so a self signed certificate is refused. */
    public void testSelfSignedIsRefusedByDefault() {
        try {
            int code = get(OkHttpClientFactory.create(ImpersonatorFactory.macChrome()).newHttpClient(), SELF_SIGNED);
            fail("expected the self signed certificate to be refused, got HTTP " + code);
        } catch (IOException e) {
            // The trust manager's CertificateException reaches the wire as this alert.
            TlsFatalAlert alert = findFatalAlert(e);
            assertNotNull("expected a TlsFatalAlert, got " + e, alert);
            assertEquals(AlertDescription.certificate_unknown, alert.getAlertDescription());
        }
    }

    /** The same client reaches a properly signed server, so the refusal above is about the chain. */
    public void testAValidCertificateIsAcceptedByDefault() throws IOException {
        assertEquals(200, get(OkHttpClientFactory.create(ImpersonatorFactory.macChrome()).newHttpClient(), VALID));
    }

    /**
     * Talking to an intercepting proxy still has to be possible, but the caller has to bring the
     * trust manager that allows it; the library no longer ships one.
     */
    public void testSelfSignedIsReachedWhenTrustingEverythingIsAskedFor() throws IOException {
        OkHttpClient client = OkHttpClientFactory.create(ImpersonatorFactory.macChrome())
                .newHttpClient(null, new TrustManager[]{new TrustAll()}, null);
        assertEquals(200, get(client, SELF_SIGNED));
    }

    private static class TrustAll implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static TlsFatalAlert findFatalAlert(Throwable t) {
        for (; t != null; t = t.getCause()) {
            if (t instanceof TlsFatalAlert) {
                return (TlsFatalAlert) t;
            }
        }
        return null;
    }

    private static int get(OkHttpClient client, String url) throws IOException {
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            return response.code();
        }
    }
}
