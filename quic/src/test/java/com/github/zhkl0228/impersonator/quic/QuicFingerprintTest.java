package com.github.zhkl0228.impersonator.quic;

import com.alibaba.fastjson2.JSONObject;
import junit.framework.TestCase;
import tech.kwik.flupke.Http3Client;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * What the QUIC ClientHello looks like from the server's side.
 * <p>
 * Scrapfly's endpoint answers over HTTP/3 only and reports the ClientHello it received, so the JA4
 * it computes is the same JA4 anyone else fingerprinting this client would compute. Matching a
 * capture of another client byte for byte is the only evidence that
 * {@link tech.kwik.agent15.engine.ClientHelloSpec} really dictates the message rather than merely
 * influencing it.
 * <p>
 * curl is the client reproduced here because nobody impersonates curl: this is about the mechanism,
 * not about passing for a browser. It exercises everything a browser profile needs - a cipher list
 * agent15 does not otherwise send, an extension order it would never choose, two key shares, and
 * X25519MLKEM768, which agent15 has no key exchange for at all.
 */
public class QuicFingerprintTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** curl 8.21.0 / ngtcp2 / OpenSSL 3.6.3, captured from the endpoint above on 2026-09-09. */
    private static final String CURL_JA4 = "q13d0312h3_55b375c5d22e_f5ac3e2d82fc";
    private static final String CURL_JA4_HASH = "16fc307196e6";

    @Override
    protected void tearDown() {
        ImpersonatorQuic.setQuicClientHello(null);
    }

    /**
     * Without a spec the ClientHello is agent15's own: one cipher suite and eight extensions, which
     * JA4 spells {@code 0108}. This is the baseline the test below has to move.
     */
    public void testWithoutASpecTheFingerprintIsAgent15s() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertTrue("expected agent15's own ClientHello, got " + fingerprint.getString("ja4"),
                fingerprint.getString("ja4").startsWith("q13d0108h3_"));
    }

    /**
     * Every part of the JA4 comes out of the ClientHello: the cipher list, the extension types and
     * the signature algorithms. Matching all three means the message really was built to order.
     */
    public void testACapturedClientHelloIsReproducedExactly() throws Exception {
        ImpersonatorQuic.setQuicClientHello(new Curl8QuicClientHello());

        JSONObject fingerprint = fingerprint();

        assertEquals(CURL_JA4, fingerprint.getString("ja4"));
        assertEquals(CURL_JA4_HASH, fingerprint.getString("ja4_hash"));
    }

    /**
     * The fields JA4 does not cover, which is where the interesting ones are: the extension order
     * (JA4 sorts the types before hashing them), and the contents of supported_groups and key_share,
     * X25519MLKEM768 among them. agent15 can generate neither of the two key shares itself; both come
     * from BouncyCastle through {@link org.bouncycastle.tls.TlsKeyShare}.
     */
    public void testTheOrderAndTheKeySharesMatchToo() throws Exception {
        ImpersonatorQuic.setQuicClientHello(new Curl8QuicClientHello());

        JSONObject tls = fingerprint().getJSONObject("tls");

        assertEquals(List.of("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"),
                names(tls.getJSONArray("cipher_suites")));
        assertEquals(List.of(57, 0, 11, 10, 16, 22, 23, 49, 13, 43, 45, 51),
                extensionTypes(tls));
        assertEquals(List.of("X25519MLKEM768 (4588)", "X25519 (29)", "secp256r1 (23)", "X448 (30)",
                        "secp384r1 (24)", "secp521r1 (25)", "ffdhe2048 (256)", "ffdhe3072 (257)"),
                names(extension(tls, 10).getJSONArray("data")));
        assertEquals(List.of("X25519MLKEM768 (4588)", "X25519 (29)"),
                names(extension(tls, 51).getJSONArray("data")));
    }

    private static JSONObject fingerprint() throws Exception {
        HttpClient client = Http3Client.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();
        HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(FINGERPRINT_URL)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());

        JSONObject fingerprint = JSONObject.parseObject(response.body());
        assertNotNull("the endpoint answers only over HTTP/3, got: " + response.body(),
                fingerprint.getJSONObject("tls"));
        return fingerprint;
    }

    private static JSONObject extension(JSONObject tls, int type) {
        for (Object extension : tls.getJSONArray("extensions")) {
            JSONObject object = (JSONObject) extension;
            if (object.getIntValue("id") == type) {
                return object;
            }
        }
        throw new AssertionError("no extension " + type + " in " + tls.getJSONArray("extensions"));
    }

    private static List<Integer> extensionTypes(JSONObject tls) {
        List<Integer> types = new ArrayList<>();
        for (Object extension : tls.getJSONArray("extensions")) {
            types.add(((JSONObject) extension).getIntValue("id"));
        }
        return types;
    }

    private static List<String> names(Iterable<?> values) {
        List<String> names = new ArrayList<>();
        for (Object value : values) {
            names.add(((JSONObject) value).getString("name"));
        }
        return names;
    }
}
