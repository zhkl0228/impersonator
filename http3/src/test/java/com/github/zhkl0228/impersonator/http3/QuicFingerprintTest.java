package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONObject;
import junit.framework.TestCase;

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

    /**
     * Without a spec the ClientHello is agent15's own: one cipher suite and eight extensions, which
     * JA4 spells {@code 0108}. This is the baseline the test below has to move.
     */
    public void testWithoutASpecTheFingerprintIsAgent15s() throws Exception {
        JSONObject fingerprint = fingerprint(Http3ClientFactory.create());

        assertTrue("expected agent15's own ClientHello, got " + fingerprint.getString("ja4"),
                fingerprint.getString("ja4").startsWith("q13d0108h3_"));
    }

    /**
     * Every part of the JA4 comes out of the ClientHello: the cipher list, the extension types and
     * the signature algorithms. Matching all three means the message really was built to order.
     */
    public void testACapturedClientHelloIsReproducedExactly() throws Exception {
        JSONObject fingerprint = fingerprint(curl());

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
        JSONObject tls = fingerprint(curl()).getJSONObject("tls");

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

    /** A factory whose profile is the captured curl ClientHello and the QUIC layer that went with it. */
    private static Http3ClientFactory curl() {
        return Http3ClientFactory.create(new Curl8QuicClientHello(), Curl8QuicTransport.create());
    }

    private static JSONObject fingerprint(Http3ClientFactory factory) throws Exception {
        String body = Http3Get.body(factory, FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
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

    /**
     * The QUIC layer, which a server reads off the packet rather than out of the ClientHello: the
     * transport parameters and the length of the connection id in the first Initial.
     * <p>
     * Two of the parameters are matched by <em>not</em> being sent. The endpoint reports 0 for
     * max_idle_timeout and 2^62-1 for max_udp_payload_size, which are what it says when a parameter
     * is absent - so what curl's capture records is that ngtcp2 sends nothing it does not have to,
     * and matching it means omitting them rather than finding a value that reads the same.
     */
    public void testTheQuicTransportParametersMatchToo() throws Exception {
        JSONObject quic = fingerprint(curl()).getJSONObject("quic");
        JSONObject parameters = quic.getJSONObject("transport_parameters");

        assertEquals(20, quic.getIntValue("dcid_length"));
        // scid_length is the endpoint's own, not this client's; see ChromeQuicFingerprintTest.

        assertEquals(1048576000L, parameters.getLongValue("initial_max_data"));
        assertEquals(32768L, parameters.getLongValue("initial_max_stream_data_bidi_local"));
        assertEquals(32768L, parameters.getLongValue("initial_max_stream_data_bidi_remote"));
        assertEquals(1048576000L, parameters.getLongValue("initial_max_stream_data_uni"));
        assertEquals(262144L, parameters.getLongValue("initial_max_streams_bidi"));
        assertEquals(262144L, parameters.getLongValue("initial_max_streams_uni"));
        assertEquals("max_idle_timeout is not sent", 0L, parameters.getLongValue("max_idle_timeout_ms"));
        assertEquals("max_udp_payload_size is not sent",
                4611686018427387903L, parameters.getLongValue("max_udp_payload_size"));
    }

    /**
     * What is still kwik's and flupke's, asserted so that it is noticed when it changes rather than
     * quietly drifting: the Initial packet's frame layout, and the HTTP/3 SETTINGS frame.
     * <p>
     * curl's Initial carries 11 CRYPTO frames with 12 single byte PADDING frames woven between them;
     * kwik puts the whole ClientHello in one CRYPTO frame and pads nothing. Matching that means
     * rebuilding kwik's packet assembly to imitate ngtcp2, and ngtcp2 is not the target - a browser
     * is, and Chrome's QUIC stack will lay its Initial out differently again. So this waits for a
     * capture of the browser rather than being built against curl.
     */
    public void testTheInitialPacketAndTheSettingsFrameAreStillNotMatched() throws Exception {
        JSONObject fingerprint = fingerprint(curl());
        JSONObject initial = fingerprint.getJSONObject("quic").getJSONArray("initial_packets").getJSONObject(0);

        assertEquals("kwik sends the ClientHello as one CRYPTO frame; curl sends eleven",
                1, initial.getJSONArray("frames").size());
        assertEquals("flupke sends two SETTINGS parameters, curl sends three",
                "1:0;7:0", fingerprint.getString("h3_text"));
    }
}
