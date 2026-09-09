package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

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
public class EchOverHttp3Test extends TestCase {

    /**
     * Cloudflare's ECH test host. Its DNS HTTPS record carries {@code alpn=h3} and {@code ech=} in
     * the same record, so the ECHConfigList a browser would use is the one HTTP/3 uses; the more
     * familiar crypto.cloudflare.com publishes only {@code alpn=h2} and refuses a QUIC handshake.
     * It is also its own ECHConfig's public_name, so a rejection still produces a usable
     * certificate for it.
     */
    private static final String HOST = "cloudflare-ech.com";
    private static final String TRACE_URL = "https://" + HOST + "/cdn-cgi/trace";

    /**
     * The ECHConfigList comes from the same DNS-over-HTTPS provider the TCP path uses, so this is
     * the whole feature in one call.
     */
    public void testEchIsAcceptedOverHttp3() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create()
                .setEchConfigProvider(DnsOverHttpsEchConfigProvider.getInstance()), TRACE_URL);
        assertTrue("expected an encrypted sni, got:\n" + body, body.contains("sni=encrypted"));
    }

    /**
     * The reverse control. Without a provider no ECH is offered at all and the server name goes out
     * in the plaintext SNI, which is what proves the test above is not measuring something else.
     */
    public void testWithoutAnEchConfigTheSniIsPlaintext() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(), TRACE_URL);
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
        Http3ClientFactory factory = Http3ClientFactory.create()
                .setEchConfigProvider(host -> corrupted)
                .setEchRejectionHandler((serverName, publicName, configs) -> {
                    rejections.incrementAndGet();
                    publicNames.add(publicName);
                    retryConfigs.add(configs);
                });

        try {
            Http3Get.body(factory, TRACE_URL);
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

        String body = Http3Get.body(Http3ClientFactory.create().setEchConfigProvider(host -> published), TRACE_URL);
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

        try {
            Http3Get.body(Http3ClientFactory.create().setEchConfigProvider(host -> unusable), TRACE_URL);
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


    /**
     * The two together: a ClientHello dictated by a profile, and a real Encrypted Client Hello inside
     * it. ECH needs two ClientHellos and the profile describes one, so it is used twice - same cipher
     * suites, same extensions in the same order, same key shares - differing only in the name, the
     * random, and the "encrypted_client_hello". The real ECH takes the slot the profile's GREASE ECH
     * was in, which is where a browser puts it.
     * <p>
     * {@code kex=X25519MLKEM768} in the same answer shows the two key shares survived the round trip:
     * the inner and the outer carry the same ones, so whichever ClientHello the server used, the
     * shared secret is the one this end holds the private half of.
     * <p>
     * This test failed two times in five until the ClientHelloInner was compressed against the outer.
     * Without that the ClientHelloOuter carried a second copy of every extension - 3422 bytes across
     * three Initial packets - and this host acknowledged all three and then never answered. Compressed
     * it is 1854 bytes in two, and the answer comes.
     */
    public void testAProfilesClientHelloCarriesARealEch() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(ImpersonatorFactory.macChrome()), TRACE_URL);

        assertTrue("expected an encrypted sni, got:\n" + body, body.contains("sni=encrypted"));
        assertTrue("expected the hybrid key share to have been used, got:\n" + body,
                body.contains("kex=X25519MLKEM768"));
    }

    /**
     * A GREASE ECH offered to a host that does publish an ECHConfig - which is what happens whenever
     * the DNS lookup fails on a host that has one. The server cannot decrypt it, so it answers with
     * retry_configs, and RFC 9849 section 6.2.1 says what to do about that: "It otherwise ignores the
     * extension. It MUST NOT save the retry_configs value in EncryptedExtensions."
     * <p>
     * This failed every time until two things were fixed. The engine matched the server's answer
     * against the extensions it sent by Java class, and a profile supplies its GREASE ECH as raw
     * bytes, so a perfectly legal answer looked like "extension response to missing request"; it
     * matches on the extension type now, which is what RFC 8446 talks about. And the engine then
     * treated the answer as an error rather than ignoring it.
     * <p>
     * The connection surviving is the whole point: on this path the alternative is that a failed DNS
     * lookup turns a working connection into a dead one, where the TCP path merely degrades to a
     * visible server name.
     */
    public void testAGreaseEchIsIgnoredByAHostThatPublishesOne() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(ImpersonatorFactory.macChrome())
                .setEchConfigProvider(null), TRACE_URL);

        assertTrue("expected the connection to survive with a visible server name, got:\n" + body,
                body.contains("sni=plaintext"));
    }

    /**
     * A ClientHello with no slot for it. Adding one would put an extension in the message that the
     * client being impersonated never sends, so this refuses rather than quietly changing the
     * fingerprint - the same reasoning as on the TCP path.
     */
    public void testAClientHelloWithNoEchSlotRefusesAnEchConfigList() throws Exception {
        byte[] echConfigList = DnsOverHttpsEchConfigProvider.getInstance().getEchConfigList(HOST);
        assertNotNull(HOST + " should publish an ECHConfigList", echConfigList);

        try {
            Http3Get.body(Http3ClientFactory.create(new Curl8QuicClientHello())
                    .setEchConfigProvider(host -> echConfigList), TRACE_URL);
            fail("a ClientHello with no encrypted_client_hello must not silently gain one");
        }
        catch (Exception e) {
            IllegalStateException refusal = null;
            for (Throwable t = e; t != null; t = t.getCause()) {
                if (t instanceof IllegalStateException) {
                    refusal = (IllegalStateException) t;
                }
            }
            assertNotNull("expected an IllegalStateException, got " + e, refusal);
            assertTrue(refusal.getMessage(),
                    refusal.getMessage().contains("carries no encrypted_client_hello extension"));
        }
    }
}
