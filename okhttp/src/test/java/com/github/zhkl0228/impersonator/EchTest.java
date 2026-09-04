package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.bouncycastle.tls.EchConfigList;
import org.bouncycastle.tls.TlsEchRejectedException;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class EchTest extends TestCase {

    private static final String TRACE_URL = "https://crypto.cloudflare.com/cdn-cgi/trace";

    /**
     * Cloudflare's trace endpoint reports {@code sni=encrypted} when the server name arrived inside
     * a ClientHelloInner, and {@code sni=plaintext} otherwise. Nothing is configured here: a profile
     * whose browser supports ECH resolves the host's ECHConfigList over DNS-over-HTTPS by itself.
     */
    public void testEchIsAcceptedWithNoConfiguration() throws Exception {
        String body = trace(null);
        assertTrue("expected an encrypted sni, got:\n" + body, body.contains("sni=encrypted"));
    }

    /**
     * With the lookup removed only the GREASE ECH goes out, which the server cannot decrypt, so the
     * server name travels in the clear. This is the baseline the previous test has to improve on,
     * and it is also what a host with no ECHConfig in DNS gets.
     */
    public void testWithoutTheLookupTheSniIsPlaintext() throws Exception {
        String body = trace(api -> api.setEchConfigProvider(null));
        assertTrue("expected a plaintext sni, got:\n" + body, body.contains("sni=plaintext"));
    }

    /**
     * Offering a config the server has no key for makes it fall back to the ClientHelloOuter and
     * publish retry_configs. This is the path where the transcript has to be rewound from the
     * ClientHelloInner to the ClientHelloOuter, so the handshake gets far enough to decrypt
     * EncryptedExtensions.
     * <p>
     * RFC 9849 6.1.6 then requires the connection to be authenticated for the public_name before
     * the retry_configs mean anything, so the recording trust manager below must have been handed
     * the server's chain by the time the exception arrives. Aborting at EncryptedExtensions, which
     * is where the retry_configs are read, would leave it untouched.
     */
    public void testEchRejectedIsReportedOnlyAfterThePublicNameIsAuthenticated() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance()
                .getEchConfigList("crypto.cloudflare.com");
        assertNotNull("crypto.cloudflare.com should publish an ECHConfigList", echConfigList);
        final byte[] corrupted = corruptPublicKey(echConfigList);
        RecordingTrustManager trustManager = new RecordingTrustManager();

        try {
            String body = trace(api -> api.setEchConfigProvider(host -> corrupted), trustManager);
            fail("expected the server to reject ECH, got:\n" + body);
        } catch (IOException e) {
            // TlsFatalAlert is an IOException, so this arrives unwrapped rather than as an SSLException.
            TlsEchRejectedException rejected = findEchRejected(e);
            assertNotNull("expected a TlsEchRejectedException, got " + e, rejected);
            assertEquals("cloudflare-ech.com", rejected.getPublicName());
            byte[] retryConfigs = rejected.getRetryConfigs();
            assertNotNull("the server should publish retry_configs", retryConfigs);
            // What comes back must be a usable ECHConfigList for the same client-facing server.
            assertEquals("cloudflare-ech.com", EchConfigList.select(retryConfigs).getPublicName());

            X509Certificate[] chain = trustManager.chain;
            assertNotNull("the handshake must reach the server certificate before reporting the rejection", chain);
            // The name the retry_configs were authenticated as, which is the ClientHelloOuter's SNI.
            assertTrue("the certificate should name cloudflare-ech.com, got " + chain[0].getSubjectX500Principal(),
                    String.valueOf(chain[0].getSubjectAlternativeNames()).contains("cloudflare-ech.com"));
        }
    }

    /**
     * Notes the chain the handshake presented and then judges it exactly as an unconfigured client
     * would. Recording it is the only way to see from outside that the rejection was reported after
     * the certificate arrived rather than at EncryptedExtensions, where the retry_configs are read.
     */
    private static class RecordingTrustManager implements X509TrustManager {
        private final X509TrustManager delegate = ImpersonatorFactory.DEFAULT_TRUST_MANAGER;
        private X509Certificate[] chain;

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            this.chain = chain;
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    /**
     * Safari does not do ECH, so its profile sends no ECH extension at all. Installing a config
     * lookup must be refused rather than adding an extension the real browser never sends.
     */
    public void testEchOnANonEchProfileIsRefused() {
        ImpersonatorApi api = ImpersonatorFactory.macSafari();
        try {
            api.setEchConfigProvider(host -> new byte[0]);
            fail("expected the provider to be refused");
        } catch (UnsupportedOperationException e) {
            assertTrue(String.valueOf(e.getMessage()),
                    String.valueOf(e.getMessage()).contains("does not support Encrypted Client Hello"));
        }
    }

    /**
     * Flip a bit of the ECHConfig's public key. The public_name is left alone, so the
     * ClientHelloOuter still goes to a name Cloudflare serves and the rejection is about ECH rather
     * than about the SNI. X25519 does not validate public keys, so the seal still succeeds and it is
     * the server that cannot open it.
     */
    private static byte[] corruptPublicKey(byte[] echConfigList) {
        // list(2) version(2) length(2) config_id(1) kem_id(2) public_key length(2) then the key.
        byte[] corrupted = echConfigList.clone();
        corrupted[2 + 4 + 1 + 2 + 2] ^= 0x01;
        return corrupted;
    }

    private static TlsEchRejectedException findEchRejected(Throwable t) {
        for (; t != null; t = t.getCause()) {
            if (t instanceof TlsEchRejectedException) {
                return (TlsEchRejectedException) t;
            }
        }
        return null;
    }

    private interface ApiCustomizer {
        void customize(ImpersonatorApi api);
    }

    private static String trace(ApiCustomizer customizer) throws Exception {
        return trace(customizer, null);
    }

    private static String trace(ApiCustomizer customizer, X509TrustManager trustManager) throws Exception {
        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        if (customizer != null) {
            customizer.customize(api);
        }
        OkHttpClientFactory factory = OkHttpClientFactory.create(api);
        OkHttpClient client = trustManager == null ? factory.newHttpClient()
                : factory.newHttpClient(null, new TrustManager[]{trustManager}, null);
        Request request = new Request.Builder().url(TRACE_URL).build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody responseBody = response.body();
            assertNotNull(responseBody);
            String body = responseBody.string();
            System.out.println(body);
            return body;
        }
    }
}
