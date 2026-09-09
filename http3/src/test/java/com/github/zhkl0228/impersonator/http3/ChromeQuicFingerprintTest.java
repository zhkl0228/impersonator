package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONArray;
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
    private static final String CHROME_H3_HASH = "049704d97f9b";

    private static final String USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36";

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
        /*
         * scid_length is not asserted, because this endpoint does not report it. It answers 4
         * whatever the client sends - that being the length of its own connection id - which was
         * checked by sending 0 and watching it still say 4. The assertion that used to be here
         * passed for the same reason it would have passed for any client, and the value it enshrined
         * (4) was read off this same field. Chrome sends none at all; see Chrome.getQuicTransport,
         * where the capture that settles it is named.
         */

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
     * The three parameters Chrome sends that RFC 9000 does not define, and that the endpoint reports
     * alongside the rest: a reserved one (RFC 9287, which it labels id 0), "version_information"
     * (RFC 9368), and Google's own {@code google_connection_options}.
     * <p>
     * The last carries the four bytes {@code ORIG}, which Chromium's {@code crypto_protocol.h} calls
     * "Experiment for sending new ORIGIN frame". It is reproduced because it is in the capture, not
     * because anything here acts on it; receiving an ORIGIN frame is harmless, since RFC 9114 has an
     * endpoint ignore frame types it does not know.
     */
    public void testTheParametersChromeSendsBeyondRfc9000AreThereToo() throws Exception {
        JSONArray parameters = fingerprint().getJSONObject("reproduction").getJSONObject("quic")
                .getJSONArray("transport_params");

        List<Integer> ids = new ArrayList<>();
        String googleConnectionOptions = null;
        for (Object value : parameters) {
            JSONObject parameter = (JSONObject) value;
            ids.add(parameter.getIntValue("id"));
            if (parameter.getIntValue("id") == 0x3128) {
                googleConnectionOptions = parameter.getString("raw");
            }
        }
        Collections.sort(ids);

        assertEquals("the same parameters Chrome sends, no more and no fewer",
                List.of(0, 1, 3, 4, 5, 6, 7, 8, 9, 15, 17, 32, 0x3128), ids);
        assertEquals("google_connection_options carrying the ORIG tag", "T1JJRw==", googleConnectionOptions);
    }

    /**
     * The reserved QUIC version offered in "version_information" has to be drawn per connection, or it
     * is a stable identifier rather than noise. Same for the reserved transport parameter beside it.
     */
    public void testTheGreasedQuicValuesChangePerConnection() throws Exception {
        assertFalse("the same version_information twice is not GREASE",
                versionInformation().equals(versionInformation()));
    }

    private static String versionInformation() throws Exception {
        for (Object value : fingerprint().getJSONObject("reproduction").getJSONObject("quic")
                .getJSONArray("transport_params")) {
            JSONObject parameter = (JSONObject) value;
            if (parameter.getIntValue("id") == 17) {
                return parameter.getString("raw");
            }
        }
        throw new AssertionError("no version_information was sent");
    }

    /**
     * The HTTP/3 SETTINGS frame: all five of Chrome's settings, with Chrome's values, in Chrome's
     * order, ending in a GREASE one. The hash is over the whole set, so it only matches when every
     * value does - four out of five leaves it as far from Chrome's as one out of five would.
     * <p>
     * Two of the values are promises about this end rather than descriptions of it.
     * QPACK_MAX_TABLE_CAPACITY and QPACK_BLOCKED_STREAMS invite the peer's encoder to keep a 64 KiB
     * dynamic table and to let a hundred streams block on entries it has not delivered yet; until the
     * decoder underneath implemented that, these two were deliberately sent as zero, because
     * advertising a capability that is not there breaks the connection rather than the fingerprint.
     * They are Chrome's now because the capability is there; {@link QpackDynamicTableTest#testTheDynamicTableIsReallyUsed}
     * is the evidence, and this test alone would not be.
     */
    public void testTheSettingsFrameIsChromes() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals("1:65536;6:262144;7:100;51:1;GREASE", fingerprint.getString("h3_text"));
        assertEquals(CHROME_H3_HASH, fingerprint.getString("h3_hash"));
    }

    /** The GREASE setting has to be drawn per connection, or it is a stable identifier instead. */
    public void testTheGreaseSettingChangesPerConnection() throws Exception {
        assertFalse("the same GREASE setting twice is not GREASE",
                greaseSetting().equals(greaseSetting()));
    }

    private static String greaseSetting() throws Exception {
        for (Object frame : fingerprint().getJSONArray("http3")) {
            for (Object setting : ((JSONObject) frame).getJSONArray("settings")) {
                JSONObject entry = (JSONObject) setting;
                if ("GREASE".equals(entry.getString("name"))) {
                    return entry.getString("id") + ":" + entry.getString("value");
                }
            }
        }
        throw new AssertionError("no GREASE setting was sent");
    }


    /**
     * The request itself, not only the handshake. A connection whose QUIC, TLS and HTTP/3
     * fingerprints match this browser byte for byte, carrying a request with no User-Agent at all,
     * is a plainer tell than any mismatch would be - and that is what this client sent until the
     * profile's headers were applied to the HTTP/3 path as they always were to the TCP one.
     * <p>
     * The endpoint echoes what it received, so this compares against the browser's own.
     */
    public void testTheRequestCarriesTheBrowsersUserAgent() throws Exception {
        assertEquals(USER_AGENT, fingerprint().getString("user_agent"));
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
