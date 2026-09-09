package com.github.zhkl0228.impersonator.quic;

import com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider;
import junit.framework.TestCase;
import tech.kwik.agent15.ech.EchException;
import tech.kwik.flupke.Http3Client;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Encrypted Client Hello over QUIC, against Cloudflare.
 * <p>
 * The host's DNS HTTPS record carries {@code alpn=h3} and {@code ech=} in the same record, so the
 * ECHConfigList a browser uses for TCP is the one it uses for HTTP/3. And {@code /cdn-cgi/trace}
 * answers with {@code sni=encrypted} or {@code sni=plaintext}, which is the only direct evidence
 * that the real server name never appeared in the clear.
 */
public class EchOverQuicTest extends TestCase {

    /**
     * Cloudflare's ECH test host. Its DNS HTTPS record carries {@code alpn=h3} and {@code ech=} in
     * the same record, so the ECHConfigList a browser would use is the one HTTP/3 uses; the more
     * familiar crypto.cloudflare.com publishes only {@code alpn=h2} and refuses a QUIC handshake.
     * It is also its own ECHConfig's public_name, so a rejection still produces a usable
     * certificate for it.
     */
    private static final String HOST = "cloudflare-ech.com";
    private static final String TRACE_URL = "https://" + HOST + "/cdn-cgi/trace";

    @Override
    protected void tearDown() {
        ImpersonatorQuic.setEchConfigProvider(null);
    }

    /**
     * The ECHConfigList comes from the same DNS-over-HTTPS provider the TCP path uses, so this is
     * the whole feature in one call.
     */
    public void testEchIsAcceptedOverHttp3() throws Exception {
        ImpersonatorQuic.setEchConfigProvider(DnsOverHttpsEchConfigProvider.getInstance());

        String body = trace();
        assertTrue("expected an encrypted sni, got:\n" + body, body.contains("sni=encrypted"));
    }

    /**
     * The reverse control. Without a provider no ECH is offered at all and the server name goes out
     * in the plaintext SNI, which is what proves the test above is not measuring something else.
     */
    public void testWithoutAnEchConfigTheSniIsPlaintext() throws Exception {
        ImpersonatorQuic.setEchConfigProvider(null);

        String body = trace();
        assertTrue("expected a plaintext sni, got:\n" + body, body.contains("sni=plaintext"));
    }

    /**
     * A config the server has no key for makes it fall back to the ClientHelloOuter and publish
     * retry_configs. RFC 9849 section 6.1.6 has the connection fail; the handler here is told what
     * to offer next, and offering that gets {@code sni=encrypted}, which is what proves the
     * retry_configs are the server's own and not the broken config coming back around.
     */
    public void testARejectedEchReportsRetryConfigsThatWork() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance().getEchConfigList(HOST);
        assertNotNull(HOST + " should publish an ECHConfigList", echConfigList);
        byte[] corrupted = corruptPublicKey(echConfigList);

        List<byte[]> retryConfigs = new ArrayList<>();
        List<String> publicNames = new ArrayList<>();
        AtomicInteger rejections = new AtomicInteger();
        ImpersonatorQuic.setEchConfigProvider(host -> corrupted, (serverName, publicName, configs) -> {
            rejections.incrementAndGet();
            publicNames.add(publicName);
            retryConfigs.add(configs);
        });

        try {
            trace();
            fail("a rejected Encrypted Client Hello must fail the connection, not report success");
        }
        catch (IOException expected) {
            assertTrue("the failure should name the rejection, got: " + expected.getMessage(),
                    expected.getMessage().contains("ech_required")
                            || expected.getMessage().contains("Encrypted Client Hello was rejected"));
        }

        assertEquals("the provider that supplied the config should hear about the rejection",
                1, rejections.get());
        assertEquals("the ClientHelloOuter went to the ECHConfig's public name",
                HOST, publicNames.get(0));
        byte[] published = retryConfigs.get(0);
        assertNotNull("Cloudflare publishes retry_configs", published);

        ImpersonatorQuic.setEchConfigProvider(host -> published);
        String body = trace();
        assertTrue("expected the retry to encrypt the sni, got:\n" + body, body.contains("sni=encrypted"));
    }

    /**
     * An ECHConfigList this implementation cannot use must not quietly turn into a plaintext SNI.
     * It is reported before a single packet is sent, and unchecked because kwik discards the
     * checked exception {@code startHandshake} declares.
     */
    public void testAnUnusableEchConfigListFailsTheConnectionRatherThanFallingBack() {
        // Version 0xfe0a, the draft-10 ECH nobody deploys any more, is the only entry.
        byte[] unusable = new byte[] { 0, 6, (byte) 0xfe, 0x0a, 0, 2, 0, 0 };
        ImpersonatorQuic.setEchConfigProvider(host -> unusable);

        try {
            trace();
            fail("an unusable ECHConfigList must not be silently ignored");
        }
        catch (Exception e) {
            EchException echException = null;
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof EchException) {
                    echException = (EchException) t;
                }
            }
            assertNotNull("expected an EchException, got " + e, echException);
            assertTrue(echException.getMessage(), echException.getMessage().contains("no usable ECHConfig"));
        }
    }

    private static String trace() throws Exception {
        HttpClient client = Http3Client.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(TRACE_URL)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
        return response.body();
    }

    /**
     * Flip one bit of the HPKE public key, which leaves the ECHConfig well formed and usable but
     * makes the server unable to open the payload, so it rejects.
     */
    private static byte[] corruptPublicKey(byte[] echConfigList) {
        byte[] corrupted = echConfigList.clone();
        // ECHConfigList length (2) + version (2) + length (2) + config_id (1) + kem_id (2) + public key length (2)
        int publicKeyOffset = 2 + 2 + 2 + 1 + 2 + 2;
        assertTrue("ECHConfigList is too short to hold a public key", corrupted.length > publicKeyOffset);
        corrupted[publicKeyOffset] ^= 0x01;
        return corrupted;
    }
}
