package com.github.zhkl0228.impersonator.http3;

import com.alibaba.fastjson2.JSONObject;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import junit.framework.TestCase;

/**
 * The two mobile profiles over HTTP/3, which send the same ClientHello as their desktop counterparts
 * and differ in the request.
 * <p>
 * That is a claim about the browsers rather than a convenience, and both halves of it have a capture
 * behind them. docs/captures/chrome-152-android-quic.json is Chrome 152 on a phone, and against the
 * macOS capture of the same version every field a server reads off the handshake is identical: the
 * JA4, the cipher suites, the twelve extensions, both key shares, all four supported groups, the nine
 * signature algorithms, every QUIC transport parameter including the three that are not RFC 9000's,
 * the connection id lengths, the 1250 byte Initial datagram and the HTTP/3 SETTINGS. What differs is
 * the user agent, and two things that are drawn per connection and differ between two connections of
 * the same browser: the extension order, which BoringSSL shuffles, and the Initial packet's frame
 * layout, which QUICHE scrambles. safari-26-ios-quic.json says the same for the other pair.
 * <p>
 * One difference is real and is not reproduced: the resumed Android capture carries a transport
 * parameter the resumed macOS one does not. See {@code Chrome.getQuicTransport}, where it is
 * described - it is a round trip time measurement, so sending a captured constant would identify this
 * client rather than hide it.
 * <p>
 * Worth asserting because it is the kind of statement that rots quietly. Nothing here would fail if a
 * mobile profile stopped answering over HTTP/3, or started answering with a ClientHello of its own:
 * the desktop tests would go on passing and the README would go on saying otherwise.
 */
public class MobileProfilesQuicTest extends TestCase {

    private static final String FINGERPRINT_URL = "https://quic.tools.scrapfly.io/api/fp/quic";

    /** From docs/captures/chrome-152-quic.json and chrome-152-android-quic.json, which agree. */
    private static final String CHROME_JA4 = "q13d0312h3_55b375c5d22e_54c9dd0422dd";
    private static final String CHROME_H3 = "1:65536;6:262144;7:100;51:1;GREASE";
    private static final String ANDROID_USER_AGENT = "Mozilla/5.0 (Linux; Android 10; K)"
            + " AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Mobile Safari/537.36";

    /** From docs/captures/safari-26-quic.json and safari-26-ios-quic.json, which agree. */
    private static final String SAFARI_JA4 = "q13d0311h3_55b375c5d22e_61548afbd53c";
    private static final String SAFARI_H3 = "1:16383;7:100;GREASE";
    private static final String IOS_USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)"
            + " AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Mobile/15E148 Safari/604.1";

    public void testAndroidIsChromeOverHttp3WithAndroidsUserAgent() throws Exception {
        JSONObject fingerprint = fingerprint(ImpersonatorFactory.android());

        assertEquals(CHROME_JA4, fingerprint.getString("ja4"));
        assertEquals(CHROME_H3, fingerprint.getString("h3_text"));
        assertEquals(ANDROID_USER_AGENT, fingerprint.getString("user_agent"));
    }

    /**
     * And it encrypts the server name, Chrome on Android doing ECH as Chrome on macOS does. This is
     * the half that would break first if the mobile profile were ever given a ClientHello of its own,
     * because ECH is carried in one.
     */
    public void testAndroidEncryptsTheServerNameToo() throws Exception {
        JSONObject ech = fingerprint(ImpersonatorFactory.android())
                .getJSONObject("tls").getJSONObject("ech");

        assertNotNull("the ClientHello carried no encrypted_client_hello", ech);
        assertTrue("the server name was not encrypted: " + ech, ech.getBooleanValue("ech_success"));
    }

    public void testIosIsSafariOverHttp3WithIosUserAgent() throws Exception {
        JSONObject fingerprint = fingerprint(ImpersonatorFactory.ios());

        assertEquals(SAFARI_JA4, fingerprint.getString("ja4"));
        assertEquals(SAFARI_H3, fingerprint.getString("h3_text"));
        assertEquals(IOS_USER_AGENT, fingerprint.getString("user_agent"));
    }

    private static JSONObject fingerprint(ImpersonatorApi profile) throws Exception {
        String body = Http3Get.body(Http3ClientFactory.create(profile), FINGERPRINT_URL);
        JSONObject fingerprint = JSONObject.parseObject(body);
        assertNotNull("the endpoint answers only over HTTP/3, got: " + body, fingerprint.getJSONObject("tls"));
        return fingerprint;
    }
}
