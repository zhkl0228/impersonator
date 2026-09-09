package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Firefox's QUIC and HTTP/3 fingerprint, from a Wireshark capture cross-checked against the
 * endpoint's report of the same connections; see docs/captures/firefox-155-quic*.
 * <p>
 * Firefox is the third QUIC stack here - neqo, where Chrome has QUICHE and Safari has Apple's own -
 * and it differs from both in ways that are worth stating because each one had to be looked at
 * rather than assumed. It greases nothing in the ClientHello where Safari greases in five places,
 * but greases two HTTP/3 settings, a transport parameter and two QUIC versions where the others
 * grease none of those. It keeps "extended_master_secret" and "renegotiation_info" over QUIC, which
 * Safari drops. It offers three key shares where the others offer two. And it draws a fresh
 * Destination Connection ID length for every connection while the others always send eight bytes.
 */
public class FirefoxQuicFingerprintTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** From docs/captures/firefox-155-quic.json. */
    private static final String FIREFOX_JA4 = "q13d0315h3_55b375c5d22e_9cac0a2e6d46";
    private static final String FIREFOX_JA4_HASH = "aed78de26df6";
    private static final String FIREFOX_JA4_R = "q13d0315h3_1301,1302,1303"
            + "_0005,000a,000d,0017,001b,001c,0022,002b,002d,0033,0039,fe0d,ff01"
            + "_0201,0203,0401,0403,0501,0503,0601,0603,0804,0805,0806";
    private static final String FIREFOX_H3_HASH = "ae2c42da46ea";
    private static final String USER_AGENT =
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:155.0) Gecko/20100101 Firefox/155.0";

    /**
     * Fifteen extensions, three cipher suites and eleven signature algorithms with ecdsa_sha1 fourth
     * - which is where Firefox's QUIC ClientHello puts it and its TCP one does not, one of three
     * places the two differ.
     */
    public void testTheClientHelloIsFirefoxs() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals(FIREFOX_JA4, fingerprint.getString("ja4"));
        assertEquals(FIREFOX_JA4_HASH, fingerprint.getString("ja4_hash"));
        assertEquals(FIREFOX_JA4_R, fingerprint.getString("ja4_r"));
        assertEquals(USER_AGENT, fingerprint.getString("user_agent"));
    }

    /**
     * The extension order, which JA4 sorts away, and the absence of GREASE, which it drops entirely.
     * Both matter: this is the one profile here whose ClientHello contains no GREASE value at all.
     */
    public void testTheOrderIsFirefoxsAndNothingIsGreased() throws Exception {
        JSONObject tls = fingerprint().getJSONObject("tls");

        assertEquals(List.of(28, 10, 23, 34, 5, 13, 65281, 16, 51, 27, 45, 43, 0, 57, 65037),
                ids(tls.getJSONArray("extensions")));
        assertEquals(List.of(4588, 29, 23, 24, 25), ids(extension(tls, 10).getJSONArray("data")));
        assertEquals("three key shares, where Chrome and Safari offer two",
                List.of(4588, 29, 23), ids(extension(tls, 51).getJSONArray("data")));

        for (Object value : tls.getJSONArray("cipher_suites")) {
            assertFalse("Firefox greases no cipher suite",
                    "GREASE".equals(((JSONObject) value).getString("name")));
        }
        for (int id : ids(tls.getJSONArray("extensions"))) {
            assertFalse("Firefox greases no extension", ImpersonatorFactory.isGrease(id));
        }
    }

    /**
     * Fourteen transport parameters, the longest list of the three browsers, including two neither of
     * the others sends: max_ack_delay, which is 20 where an absent one would mean 25, and
     * max_datagram_frame_size.
     */
    public void testTheQuicTransportParametersAreFirefoxs() throws Exception {
        JSONObject parameters = fingerprint().getJSONObject("quic").getJSONObject("transport_parameters");

        assertEquals(25165824L, parameters.getLongValue("initial_max_data"));
        assertEquals(12582912L, parameters.getLongValue("initial_max_stream_data_bidi_local"));
        assertEquals("the two bidirectional limits differ, which no other profile here needs",
                1048576L, parameters.getLongValue("initial_max_stream_data_bidi_remote"));
        assertEquals(1048576L, parameters.getLongValue("initial_max_stream_data_uni"));
        assertEquals(100L, parameters.getLongValue("initial_max_streams_bidi"));
        assertEquals(100L, parameters.getLongValue("initial_max_streams_uni"));
        assertEquals(30000L, parameters.getLongValue("max_idle_timeout_ms"));
        assertEquals(20, parameters.getIntValue("max_ack_delay_ms"));
        assertEquals(8, parameters.getIntValue("active_connection_id_limit"));
        assertEquals(65535L, parameters.getLongValue("max_datagram_frame_size"));
    }

    /**
     * The HTTP/3 SETTINGS: a 64 KiB QPACK table, twenty blocked streams, extended CONNECT, HTTP
     * datagrams, and two GREASE settings. Firefox is the only profile here that sends
     * ENABLE_CONNECT_PROTOCOL and the only one that greases twice.
     */
    public void testTheSettingsFrameIsFirefoxs() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals("1:65536;7:20;8:1;51:1;GREASE;GREASE", fingerprint.getString("h3_text"));
        assertEquals(FIREFOX_H3_HASH, fingerprint.getString("h3_hash"));
    }

    /**
     * The Destination Connection ID length is drawn per connection, not fixed. This is neqo's
     * ConnectionId::generate_initial - {@code max(8, 5 + (v & (v >> 4)))} for a random byte v - which
     * lands between 8 and 20 and picks 8 more than half the time, and four captured Firefox
     * connections gave 8, 13, 14 and 19.
     * <p>
     * So the assertion is on the shape of the distribution rather than on any one value: a length
     * outside the range would be wrong, and a length that never varied would be wrong in the way that
     * matters, since never varying is the tell.
     */
    public void testTheConnectionIdLengthVariesTheWayNeqoDrawsIt() throws Exception {
        Set<Integer> lengths = new HashSet<>();
        for (int i = 0; i < 8; i++) {
            int length = fingerprint().getJSONObject("quic").getIntValue("dcid_length");
            assertTrue("neqo picks between 8 and 20, got " + length, length >= 8 && length <= 20);
            lengths.add(length);
        }
        assertTrue("eight connections all chose the same length, so it is not being drawn at all",
                lengths.size() > 1);
        assertTrue("8 is picked more than half the time, so it should be among eight draws",
                lengths.contains(8));
    }


    /**
     * Firefox does Encrypted Client Hello over QUIC, and the capture is of a connection where it
     * worked - the endpoint reported ech_success against its own ECHConfig. So this profile has to do
     * it too, and the "encrypted_client_hello" in the extension list above is a real one rather than
     * the GREASE that stands in when a host publishes no config.
     * <p>
     * Worth asserting separately from the fingerprint because the two can pass independently: the
     * ClientHello can carry the extension in the right place and still fail to encrypt anything, and
     * the only way to tell from outside is to ask a host that says which name it saw.
     */
    public void testItReallyEncryptsTheServerName() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(ImpersonatorFactory.macFirefox())
                .setEchConfigProvider(DnsOverHttpsEchConfigProvider.getInstance()),
                "https://cloudflare-ech.com/cdn-cgi/trace");

        assertTrue("expected an encrypted server name, got:\n" + body, body.contains("sni=encrypted"));
    }

    private static JSONObject fingerprint() throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(ImpersonatorFactory.macFirefox()), FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
        return fingerprint;
    }

    private static JSONObject extension(JSONObject tls, int type) {
        for (Object value : tls.getJSONArray("extensions")) {
            JSONObject extension = (JSONObject) value;
            if (extension.getIntValue("id") == type) {
                return extension;
            }
        }
        throw new AssertionError("no extension " + type + " in " + tls.getJSONArray("extensions"));
    }

    private static List<Integer> ids(JSONArray values) {
        List<Integer> ids = new ArrayList<>();
        for (Object value : values) {
            ids.add(((JSONObject) value).getIntValue("id"));
        }
        return ids;
    }
}
