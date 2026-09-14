package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.DnsOverHttpsEchConfigProvider;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;

import junit.framework.TestCase;

import java.util.ArrayList;
import java.util.List;

/**
 * Safari's QUIC and HTTP/3 fingerprint, against the same endpoint the browser was measured on.
 * <p>
 * The profile is built from a Wireshark capture of Safari 26.6.2, cross-checked against what the
 * endpoint reported for that same connection - the capture's connection id appears in the JSON, so
 * the two describe one handshake. Where they disagreed the capture won, twice: the endpoint says the
 * client's source connection id is four bytes and that its Initial datagrams are 1250 bytes, and
 * neither is true of Safari. It reports the same two numbers for Chrome, which is how they were
 * found out.
 * <p>
 * iOS Safari 26.6 produces a byte identical fingerprint - same JA4, same HTTP/3 settings, same
 * transport parameters - so one profile serves both, as it already did for TCP.
 */
public class SafariQuicFingerprintTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** From the capture of Safari 26.6.2, and identical from iOS Safari 26.6. */
    private static final String SAFARI_JA4 = "q13d0311h3_55b375c5d22e_f2a83c8e78ae";
    private static final String SAFARI_JA4_HASH = "fe9999b49816";
    private static final String SAFARI_JA4_R = "q13d0311h3_1301,1302,1303"
            + "_0005,000a,000d,0012,001b,002b,002d,0033,0039"
            + "_0403,0804,0401,0503,0805,0805,0501,0806,0601,0201";
    private static final String SAFARI_H3_HASH = "56334358583c";

    /** From docs/captures/safari-26-quic-resumed.json - Safari's ClientHello after a refresh. */
    private static final String SAFARI_RESUMED_JA4 = "q13d0313h3_55b375c5d22e_6bb9a3ac9a4b";

    /** From the same capture; iOS Safari differs from macOS Safari in this and nothing else. */
    private static final String USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
            + " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6.2 Safari/605.1.15";

    /**
     * The ClientHello, which is where most of Safari shows: eleven extensions to Chrome's twelve,
     * three cipher suites in a different order, and a signature algorithm list that offers
     * rsa_pss_rsae_sha384 twice - visible in the JA4_r as the repeated 0805, and the same oddity the
     * TCP profile records.
     */
    public void testTheClientHelloIsSafaris() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals(SAFARI_JA4, fingerprint.getString("ja4"));
        assertEquals(SAFARI_JA4_HASH, fingerprint.getString("ja4_hash"));
        assertEquals(SAFARI_JA4_R, fingerprint.getString("ja4_r"));
    }

    /**
     * What JA4 leaves out: the extension order, and the GREASE. Safari greases in five places where
     * Chrome's QUIC ClientHello greases in none - a cipher suite, an extension at each end of the
     * list, a named group, and the key share entry that goes with that group, which carries a single
     * byte because there is no key exchange to fill it.
     */
    public void testTheOrderAndTheGreaseAreSafaris() throws Exception {
        JSONObject tls = fingerprint().getJSONObject("tls");

        assertEquals(List.of("GREASE", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                        "TLS_AES_128_GCM_SHA256"),
                names(tls.getJSONArray("cipher_suites")));
        List<Integer> extensions = ids(tls.getJSONArray("extensions"));
        assertEquals("eleven extensions between two GREASE ones", 13, extensions.size());
        assertEquals(List.of(0, 10, 16, 5, 13, 18, 51, 45, 43, 57, 27),
                extensions.subList(1, extensions.size() - 1));
        assertTrue("the first extension should be GREASE", isGrease(extensions.getFirst()));
        assertTrue("the last extension should be GREASE", isGrease(extensions.getLast()));

        List<Integer> groups = ids(extension(tls, 10).getJSONArray("data"));
        List<Integer> keyShares = ids(extension(tls, 51).getJSONArray("data"));
        assertEquals(List.of(4588, 29, 23, 24, 25), groups.subList(1, groups.size()));
        assertEquals(List.of(4588, 29), keyShares.subList(1, keyShares.size()));
        assertTrue("supported_groups should begin with a GREASE group", isGrease(groups.getFirst()));
        assertEquals("the key share greases with the same value as the group list",
                groups.getFirst(), keyShares.getFirst());
    }

    /**
     * The transport parameters, which are six where Chrome sends thirteen. The absences are the
     * fingerprint as much as the values: no max_idle_timeout, no max_udp_payload_size, no
     * initial_max_streams_bidi, no ack_delay_exponent, no max_ack_delay and no GREASE. The endpoint
     * reports a default for each of those, which is what it says when a parameter is not sent.
     */
    public void testTheQuicTransportParametersAreSafaris() throws Exception {
        JSONObject quic = fingerprint().getJSONObject("quic");
        JSONObject parameters = quic.getJSONObject("transport_parameters");

        assertEquals(8, quic.getIntValue("dcid_length"));

        assertEquals(16777216L, parameters.getLongValue("initial_max_data"));
        assertEquals(2097152L, parameters.getLongValue("initial_max_stream_data_bidi_local"));
        assertEquals(2097152L, parameters.getLongValue("initial_max_stream_data_bidi_remote"));
        assertEquals(2097152L, parameters.getLongValue("initial_max_stream_data_uni"));
        assertEquals(8L, parameters.getLongValue("initial_max_streams_uni"));
        assertEquals(64, parameters.getIntValue("active_connection_id_limit"));

        assertEquals("initial_max_streams_bidi is not sent", 0L,
                parameters.getLongValue("initial_max_streams_bidi"));
        assertEquals("max_idle_timeout is not sent", 0L, parameters.getLongValue("max_idle_timeout_ms"));
        assertEquals("max_udp_payload_size is not sent",
                4611686018427387903L, parameters.getLongValue("max_udp_payload_size"));
        assertEquals("ack_delay_exponent is not sent", 3, parameters.getIntValue("ack_delay_exponent"));
        assertEquals("max_ack_delay is not sent", 25, parameters.getIntValue("max_ack_delay_ms"));
    }

    /**
     * The HTTP/3 SETTINGS: a 16 KiB QPACK table and a hundred blocked streams, and nothing else but a
     * GREASE. Safari sends neither MAX_FIELD_SECTION_SIZE nor H3_DATAGRAM, both of which Chrome does.
     * Both of the values it does send are promises the QPACK decoder underneath keeps.
     */
    public void testTheSettingsFrameIsSafaris() throws Exception {
        JSONObject fingerprint = fingerprint();

        assertEquals("1:16383;7:100;GREASE", fingerprint.getString("h3_text"));
        assertEquals(SAFARI_H3_HASH, fingerprint.getString("h3_hash"));
    }


    /**
     * Safari's first Initial packet: one CRYPTO frame of 999 bytes and 162 bytes of PADDING behind
     * it, where filling the packet would leave none.
     * <p>
     * Safari sends its ClientHello in order and simply stops early, which is neither Chrome's
     * scrambling nor Firefox's cut at the server name, and neither is it kwik's "fill each packet
     * until the data runs out" - that produces a first Initial with no padding at all, which is what
     * this client sent until now. All three Safari captures report the same 162, the resumed one
     * included, and a packet capture shows the frames themselves: CRYPTO[0,999) then PADDING x162,
     * and CRYPTO[999,1485) after it. See docs/captures/safari-26-quic-initial-2.pcapng and
     * {@link tech.kwik.core.crypto.InitialCryptoDivision.FixedChunks}.
     * <p>
     * The padding is asserted rather than the 999 because the endpoint reports the padding and not
     * the frame length - but with an 8 byte connection id and a 1200 byte datagram the two are the
     * same statement, 162 being exactly what a 999 byte frame leaves.
     * <p>
     * One CRYPTO frame and the padding length, rather than the whole frame list: the endpoint reports
     * the padding twice over, once as a length and once as a run of PADDING frames, and the capture
     * files here have only the length. What both agree on is the number this is about.
     * <p>
     * And either of the two packets, because the endpoint reports one Initial packet and does not say
     * which datagram it is. Usually the first; under load, when the two are processed out of order,
     * the second. Both numbers come from the same cut and from nothing else: 162 is what a 999 byte
     * CRYPTO frame and its 4 byte header leave of the 1165 bytes a 1200 byte Initial datagram carries,
     * and 675 is what the 485 bytes that follow them and their 5 byte header leave. A different
     * division shows up as a third number, and a ClientHello of a different length as a different
     * second one - so the message carries what was actually seen.
     */
    public void testTheFirstInitialCarriesSafarisNineHundredAndNinetyNineBytes() throws Exception {
        JSONObject initial = fingerprint().getJSONObject("quic")
                .getJSONArray("initial_packets").getJSONObject(0);

        int crypto = 0;
        for (Object frame : initial.getJSONArray("frames")) {
            if (((Number) frame).intValue() == 6) {
                crypto++;
            }
        }
        assertEquals("one CRYPTO frame, as in every capture", 1, crypto);
        int padding = initial.getIntValue("padding_length");
        assertTrue("999 bytes of ClientHello in a 1200 byte datagram leave 162, and the 485 that"
                        + " follow them leave 675; this packet left " + padding,
                padding == 162 || padding == 675);
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


    /**
     * Safari does not do Encrypted Client Hello, so asking this profile for it is refused rather than
     * quietly obliged. Offering a real one would put an extension in the ClientHello that this
     * browser never sends, which makes the connection less like Safari and not more - the same
     * contract the TCP path has always had, and which the HTTP/3 factory did not enforce until now.
     */
    public void testAnEchConfigProviderIsRefused() {
        try {
            Http3ClientFactory.create(ImpersonatorFactory.macSafari())
                    .setEchConfigProvider(DnsOverHttpsEchConfigProvider.getInstance());
            fail("a browser that does not do ECH must not accept an ECHConfig provider");
        }
        catch (UnsupportedOperationException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("Encrypted Client Hello"));
        }
    }

    /**
     * The second connection resumes, and its ClientHello is Safari's resumed one: thirteen extensions
     * where the first had eleven, with "early_data" between psk_key_exchange_modes and
     * supported_versions and "pre_shared_key" last of all - after the trailing GREASE, which is where
     * RFC 8446 section 4.2.11 puts it and where the capture has it.
     * <p>
     * Safari's extension order is a fixed list, unlike Chrome's per-connection shuffle, so there was
     * nowhere to put the two extra extensions until a capture of it refreshing a page said where.
     * Until then this profile did not resume at all, on the grounds that a JA4 no Safari has sent is
     * worse than the one it sends every time.
     */
    public void testTheSecondConnectionIsSafarisResumedClientHello() throws Exception {
        Http3ClientFactory factory = Http3ClientFactory.create(ImpersonatorFactory.macSafari());

        assertEquals("the first connection has no ticket to offer", SAFARI_JA4, ja4(factory));
        assertEquals(SAFARI_RESUMED_JA4, ja4(factory));
        assertEquals("a ticket is used once, so the third connection needs one of its own",
                SAFARI_RESUMED_JA4, ja4(factory));
    }

    private static String ja4(Http3ClientFactory factory) throws Exception {
        String body = Http3Get.body(factory, FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
        return fingerprint.getString("ja4");
    }

    private static boolean isGrease(int value) {
        return com.github.zhkl0228.impersonator.ImpersonatorFactory.isGrease(value);
    }

    private static JSONObject fingerprint() throws Exception {
        ImpersonatorApi safari = ImpersonatorFactory.macSafari();
        String body = Http3Get.body(Http3ClientFactory.create(safari), FINGERPRINT_URL);
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

    private static List<String> names(JSONArray values) {
        List<String> names = new ArrayList<>();
        for (Object value : values) {
            names.add(((JSONObject) value).getString("name"));
        }
        return names;
    }
}
