package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.bouncycastle.tls.EchConfigList;
import org.bouncycastle.tls.TlsEchRejectedException;

import java.io.IOException;

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
     */
    public void testEchRejectedCarriesRetryConfigs() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance()
                .getEchConfigList("crypto.cloudflare.com");
        assertNotNull("crypto.cloudflare.com should publish an ECHConfigList", echConfigList);
        final byte[] corrupted = corruptPublicKey(echConfigList);

        try {
            String body = trace(api -> api.setEchConfigProvider(host -> corrupted));
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
        ImpersonatorApi api = ImpersonatorFactory.macChrome();
        if (customizer != null) {
            customizer.customize(api);
        }
        OkHttpClient client = OkHttpClientFactory.create(api).newHttpClient();
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
