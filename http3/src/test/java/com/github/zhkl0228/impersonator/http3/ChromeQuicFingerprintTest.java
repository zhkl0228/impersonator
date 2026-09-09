package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/**
 * The Chrome profile against the capture it was written from.
 * <p>
 * {@code docs/captures/chrome-152-quic.json} is Chrome 152.0.7977.84 as this same endpoint saw it.
 * Everything asserted here is a value read out of that file, so when Chrome changes, this fails and
 * the fix is a fresh capture rather than a guess.
 */
public class ChromeQuicFingerprintTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** From docs/captures/chrome-152-quic.json. */
    private static final String CHROME_JA4 = "q13d0312h3_55b375c5d22e_54c9dd0422dd";
    private static final String CHROME_JA4_HASH = "62c61f544d54";
    private static final String CHROME_JA4_R = "q13d0312h3_1301,1302,1303"
            + "_000a,000d,001b,002b,002d,0033,0039,44cd,ca34,fe0d"
            + "_0201,0401,0403,0501,0503,0601,0804,0805,0806";

    public void testTheClientHelloIsChromes() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals(CHROME_JA4, fingerprint.getString("ja4"));
        assertEquals(CHROME_JA4_HASH, fingerprint.getString("ja4_hash"));
        assertEquals(CHROME_JA4_R, fingerprint.getString("ja4_r"));
    }

    /** The extensions Chrome sends on a full handshake, from the first capture. */
    private static final List<Integer> CHROME_EXTENSIONS =
            List.of(0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 51764, 65037);

    public void testTheExtensionsAndTheKeySharesAreChromes() throws Exception {
        JSONObject tls = fingerprint().getJSONObject("tls");

        List<Integer> sent = new ArrayList<>(ids(tls, "extensions"));
        Collections.sort(sent);
        assertEquals(CHROME_EXTENSIONS, sent);

        assertEquals(List.of(4865, 4866, 4867), ids(tls, "cipher_suites"));
        assertEquals("X25519MLKEM768, X25519, secp256r1, secp384r1",
                List.of(4588, 29, 23, 24), idsOf(tls, 10));
        assertEquals("X25519MLKEM768 and X25519, two real key shares",
                List.of(4588, 29), idsOf(tls, 51));
    }

    /**
     * Chrome shuffles the extension order on every connection - BoringSSL permutes them - so a fixed
     * order would be the one thing here no real Chrome ever sends twice. The two captures show it:
     * the same twelve extensions arrive as 43, 45, 57, 16, 13, 51, 0, 51764, 27, 65037, 17613, 10 and
     * then, after a refresh, as 17613, 51764, 0, 13, 16, 65037, 43, 27, 42, 57, 51, 10, 45, 41.
     * <p>
     * This is also why the JA4 above is stable while the order is not: JA4 sorts the extension types
     * before hashing them.
     */
    public void testTheExtensionOrderIsShuffledPerConnection() throws Exception {
        List<Integer> first = ids(fingerprint().getJSONObject("tls"), "extensions");
        List<Integer> second = ids(fingerprint().getJSONObject("tls"), "extensions");

        assertEquals("the same extensions either way", new HashSet<>(first), new HashSet<>(second));
        assertFalse("two connections sent the extensions in the same order: " + first
                        + "; with twelve extensions that is a one in 479001600 coincidence, so it is far"
                        + " more likely the order is fixed",
                first.equals(second));
    }

    /**
     * The QUIC layer, which a server reads off the packet. Chrome shuffles the order these go out in,
     * so what is asserted is the set and the values.
     */
    public void testTheQuicTransportParametersAreChromes() throws Exception {
        JSONObject quic = fingerprint().getJSONObject("quic");
        JSONObject parameters = quic.getJSONObject("transport_parameters");

        assertEquals(8, quic.getIntValue("dcid_length"));
        assertEquals(4, quic.getIntValue("scid_length"));

        assertEquals(15728640L, parameters.getLongValue("initial_max_data"));
        assertEquals(6291456L, parameters.getLongValue("initial_max_stream_data_bidi_local"));
        assertEquals(6291456L, parameters.getLongValue("initial_max_stream_data_bidi_remote"));
        assertEquals(6291456L, parameters.getLongValue("initial_max_stream_data_uni"));
        assertEquals(100L, parameters.getLongValue("initial_max_streams_bidi"));
        assertEquals(103L, parameters.getLongValue("initial_max_streams_uni"));
        assertEquals(30000L, parameters.getLongValue("max_idle_timeout_ms"));
        assertEquals(1472L, parameters.getLongValue("max_udp_payload_size"));
        assertEquals(65536L, parameters.getLongValue("max_datagram_frame_size"));
    }

    /**
     * The HTTP/3 SETTINGS frame is flupke's and is the last thing that still says so. Chrome sends
     * four settings and a GREASE one; flupke sends two, and there is no public way to change that -
     * its settings map is protected and a HashMap, so even the order is not ours to pick. Asserted so
     * that it is noticed rather than assumed.
     */
    public void testTheSettingsFrameIsStillFlupkes() throws Exception {
        assertEquals("1:0;7:0", fingerprint().getString("h3_text"));
    }

    private static JSONObject fingerprint() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(ImpersonatorFactory.macChrome()), FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
        return fingerprint;
    }

    private static List<Integer> ids(JSONObject tls, String field) {
        List<Integer> ids = new ArrayList<>();
        for (Object value : tls.getJSONArray(field)) {
            ids.add(((JSONObject) value).getIntValue("id"));
        }
        return ids;
    }

    /** The ids inside one extension's data, e.g. the named groups of supported_groups. */
    private static List<Integer> idsOf(JSONObject tls, int extensionType) {
        for (Object value : tls.getJSONArray("extensions")) {
            JSONObject extension = (JSONObject) value;
            if (extension.getIntValue("id") == extensionType) {
                List<Integer> ids = new ArrayList<>();
                for (Object entry : extension.getJSONArray("data")) {
                    ids.add(((JSONObject) entry).getIntValue("id"));
                }
                return ids;
            }
        }
        throw new AssertionError("no extension " + extensionType);
    }
}
