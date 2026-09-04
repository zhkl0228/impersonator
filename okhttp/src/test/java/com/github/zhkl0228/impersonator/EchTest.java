package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

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
     * publish retry_configs. RFC 9849 6.1.6 has the client come back with those, which the client
     * built here does by itself, so the provider keeps handing out the broken config and the
     * request still succeeds.
     * <p>
     * That the retry reports {@code sni=encrypted} is what proves it used what the server
     * published: the only other config in play is the broken one.
     * <p>
     * The chains are the other half. The rejected handshake went to the ECHConfig's public_name, so
     * its certificate is Cloudflare's client-facing one; seeing it at all means the rejection was
     * reported after the certificate arrived rather than at EncryptedExtensions, where the
     * retry_configs are read but nothing has been authenticated yet.
     */
    public void testARejectedEchIsRetriedWithWhatTheServerPublished() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance()
                .getEchConfigList("crypto.cloudflare.com");
        assertNotNull("crypto.cloudflare.com should publish an ECHConfigList", echConfigList);
        final byte[] corrupted = corruptPublicKey(echConfigList);
        RecordingTrustManager trustManager = new RecordingTrustManager();

        String body = trace(api -> api.setEchConfigProvider(host -> corrupted), trustManager);
        assertTrue("expected the retry to encrypt the sni, got:\n" + body, body.contains("sni=encrypted"));

        List<X509Certificate[]> chains = trustManager.chains;
        assertTrue("expected a rejected handshake and then a retry, got " + chains.size() + " handshakes",
                chains.size() >= 2);
        assertTrue("the rejected handshake must have reached the certificate for cloudflare-ech.com",
                namesOf(chains.get(0)).contains("cloudflare-ech.com"));
        // The retry had its ECH accepted, so the certificate is the one for the encrypted inner name.
        assertTrue("the retry should be served the certificate for the real host",
                namesOf(chains.get(chains.size() - 1)).contains("crypto.cloudflare.com"));
    }

    /**
     * A server that publishes no retry_configs is saying to stop offering ECH to it, so the next
     * connection carries a plaintext server name again.
     */
    public void testNoRetryConfigsDisablesEchForTheHost() throws Exception {
        String body = trace(api -> {
            try {
                // onEchRejected is on the class, not on ImpersonatorApi.
                ((ImpersonatorFactory) api).onEchRejected("crypto.cloudflare.com", null);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        assertTrue("expected a plaintext sni, got:\n" + body, body.contains("sni=plaintext"));
    }

    /**
     * Configs naming algorithms this library does not implement are refused rather than remembered.
     * Storing them would spend the next connection to the host on a rejection we could have seen
     * coming, and would bury the fact that the server moved on to something we do not support.
     */
    public void testUnusableRetryConfigsAreRefused() {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance()
                .getEchConfigList("crypto.cloudflare.com");
        assertNotNull("crypto.cloudflare.com should publish an ECHConfigList", echConfigList);
        byte[] unknownKem = echConfigList.clone();
        // list(2) version(2) length(2) config_id(1) then the kem_id.
        unknownKem[2 + 4 + 1] = (byte) 0xff;
        unknownKem[2 + 4 + 2] = (byte) 0xff;

        try {
            ((ImpersonatorFactory) ImpersonatorFactory.macChrome())
                    .onEchRejected("crypto.cloudflare.com", unknownKem);
            fail("expected the unusable retry_configs to be refused");
        } catch (IOException e) {
            assertTrue(String.valueOf(e.getMessage()),
                    String.valueOf(e.getMessage()).contains("no usable ECHConfig"));
        }
    }

    private static String namesOf(X509Certificate[] chain) throws CertificateParsingException {
        return String.valueOf(chain[0].getSubjectAlternativeNames());
    }

    /**
     * Notes every chain the handshakes presented and then judges each exactly as an unconfigured
     * client would. Recording them is the only way to see from outside how far a handshake got
     * before it was abandoned.
     */
    private static class RecordingTrustManager implements X509TrustManager {
        private final X509TrustManager delegate = ImpersonatorFactory.DEFAULT_TRUST_MANAGER;
        private final List<X509Certificate[]> chains = new CopyOnWriteArrayList<>();

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            delegate.checkClientTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            chains.add(chain);
            delegate.checkServerTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return delegate.getAcceptedIssuers();
        }
    }

    /**
     * Safari does not do ECH, so its profile sends no ECH extension at all. Installing a config
     * lookup must be refused rather than adding an extension the real browser never sends, and the
     * profile has to say so beforehand, so that generic setup code does not have to carry a list of
     * which browsers do ECH.
     */
    public void testEchOnANonEchProfileIsRefused() {
        ImpersonatorApi api = ImpersonatorFactory.macSafari();
        assertFalse(api.isEchSupported());
        try {
            api.setEchConfigProvider(host -> new byte[0]);
            fail("expected the provider to be refused");
        } catch (UnsupportedOperationException e) {
            assertTrue(String.valueOf(e.getMessage()),
                    String.valueOf(e.getMessage()).contains("does not support Encrypted Client Hello"));
        }
    }

    /** The profiles that do ECH say so, which is what makes the guard above usable. */
    public void testTheEchProfilesReportThatTheySupportIt() {
        assertTrue(ImpersonatorFactory.macChrome().isEchSupported());
        assertTrue(ImpersonatorFactory.android().isEchSupported());
        assertTrue(ImpersonatorFactory.macFirefox().isEchSupported());
        assertFalse(ImpersonatorFactory.ios().isEchSupported());
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
