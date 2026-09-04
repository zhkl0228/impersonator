package com.github.zhkl0228.impersonator;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClientFactory;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okhttp3.SocketFactory;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.concurrent.TimeUnit;

abstract class SSLProviderTest extends TestCase {

    /**
     * Longer than okhttp's 10 second default: these tests talk to third party fingerprinting
     * services, and tls.peet.ws in particular has been seen taking over 10 seconds to answer.
     */
    private static final long READ_TIMEOUT_SECONDS = 15;

    protected abstract ImpersonatorApi createImpersonatorApi();

    protected final JSONObject doTestURL(String url) throws Exception {
        return doTestURL(url, true);
    }

    /**
     * @param ech false to strip the ECHConfig lookup that browsers supporting ECH install by
     *            default, leaving only the GREASE ECH. The fingerprint then describes the
     *            ClientHello as it appears on the wire rather than the ClientHelloInner.
     */
    protected final JSONObject doTestURL(String url, boolean ech) throws Exception {
        ImpersonatorApi api = createImpersonatorApi();
        if (!ech) {
            api.setEchConfigProvider(null);
        }
        OkHttpClientFactory okHttpClientFactory = OkHttpClientFactory.create(api)
                .setReadTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        OkHttpClient client = this instanceof SocketFactory ? okHttpClientFactory.newHttpClient((SocketFactory) this) : okHttpClientFactory.newHttpClient();
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            assertNotNull(body);
            String json = body.string();
            JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
            return obj;
        }
    }

    /**
     * The same fingerprint check, but with the server name encrypted. tls.browserleaks.com publishes
     * an ECHConfig, and a server that accepts ECH goes on to process the ClientHelloInner only, so
     * what comes back describes the inner. The point is that turning ECH on must not disturb the
     * impersonated cipher suites, extension set, groups, ALPN or HTTP/2 settings that the origin
     * ends up seeing.
     * <p>
     * Only for profiles whose browser actually does ECH; they resolve the ECHConfigList themselves,
     * so nothing has to be configured here.
     */
    protected final void doTestBrowserLeaksEch(String ja3n_text, String userAgent,
                                               String akamai_text) throws Exception {
        JSONObject obj = doTestURL("https://tls.browserleaks.com/json", true);
        String ja3n_hash = DigestUtils.md5Hex(ja3n_text);
        assertEquals(String.format("\nExpected :%s\nActual   :%s", ja3n_text, obj.getString("ja3n_text")),
                ja3n_hash, obj.getString("ja3n_hash"));
        if (userAgent != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", userAgent, obj.getString("user_agent")),
                    userAgent, obj.getString("user_agent"));
        }
        // The HTTP/2 fingerprint is settled after the handshake, so encrypting the server name must
        // leave it untouched.
        String akamai_hash = akamai_text == null ? null : DigestUtils.md5Hex(akamai_text);
        if (akamai_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", akamai_text, obj.getString("akamai_text")),
                    akamai_hash, obj.getString("akamai_hash"));
        }
    }

    protected void doTestBrowserLeaks(String ja3n_text, String ja3_text,
                                      String userAgent,
                                      String akamai_text) throws Exception {
        JSONObject obj = doTestURL("https://tls.browserleaks.com/json", false);
        String ja3_hash = ja3_text == null ? null : DigestUtils.md5Hex(ja3_text);
        if (ja3_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", ja3_text, obj.getString("ja3_text")),
                    ja3_hash, obj.getString("ja3_hash"));
        }
        String ja3n_hash = ja3n_text == null ? null : DigestUtils.md5Hex(ja3n_text);
        assertEquals(String.format("\nExpected :%s\nActual   :%s", ja3n_text, obj.getString("ja3n_text")),
                ja3n_hash, obj.getString("ja3n_hash"));
        if (userAgent != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", userAgent, obj.getString("user_agent")), userAgent, obj.getString("user_agent"));
        }
        String akamai_hash = akamai_text == null ? null : DigestUtils.md5Hex(akamai_text);
        if (akamai_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", akamai_text, obj.getString("akamai_text")),
                    akamai_hash, obj.getString("akamai_hash"));
        }
    }

    protected final void doTestScrapFlyJa3(String scrapfly_fp) throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/fp/ja3");
        String actual = normalizeGreaseSignatureAlgs(obj.getString("scrapfly_fp"));
        assertEquals(String.format("\nExpected :%s\nActual   :%s", scrapfly_fp, actual), scrapfly_fp, actual);
    }

    /**
     * These services write GREASE as the literal "GREASE" in the cipher, group and version lists,
     * but leave it as a number in signature_algs. A browser draws a fresh GREASE value per
     * connection, so that number varies from run to run and has to be normalized before comparing.
     */
    private static String normalizeGreaseSignatureAlgs(String scrapfly_fp) {
        int start = scrapfly_fp.indexOf("|signature_algs:");
        if (start < 0) {
            return scrapfly_fp;
        }
        start += "|signature_algs:".length();
        int end = scrapfly_fp.indexOf('|', start);
        if (end < 0) {
            end = scrapfly_fp.length();
        }
        return scrapfly_fp.substring(0, start) + normalizeGrease(scrapfly_fp.substring(start, end))
                + scrapfly_fp.substring(end);
    }

    /** browserscan's fingerprint keeps the signature algorithms in its third '|' separated field. */
    private static String normalizeBrowserScanSignatureAlgs(String fp) {
        String[] fields = fp.split("\\|", -1);
        int signatureAlgs = 2;
        if (signatureAlgs >= fields.length) {
            return fp;
        }
        fields[signatureAlgs] = normalizeGrease(fields[signatureAlgs]);
        return String.join("|", fields);
    }

    private static String normalizeGrease(String dashSeparated) {
        StringBuilder normalized = new StringBuilder();
        for (String token : dashSeparated.split("-")) {
            if (normalized.length() > 0) {
                normalized.append('-');
            }
            boolean grease;
            try {
                grease = ImpersonatorFactory.isGrease(Integer.parseInt(token));
            } catch (NumberFormatException e) {
                grease = false; // already normalized to "GREASE", or not a number
            }
            normalized.append(grease ? "GREASE" : token);
        }
        return normalized.toString();
    }

    protected final void doTestScrapFlyHttp2(String http2_fingerprint,
                                             String headers_fp) throws Exception {
        doTestScrapFlyHttp2(http2_fingerprint, headers_fp, null);
    }

    /**
     * @param orderedHeaders the header names in the order they must go on the wire, comma joined.
     *                       headers_fp is alphabetical and so says nothing about order, but the
     *                       order is itself a fingerprint, so pin it where a real capture is known.
     */
    protected final void doTestScrapFlyHttp2(String http2_fingerprint,
                                             String headers_fp,
                                             String orderedHeaders) throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/http2");
        if (orderedHeaders != null) {
            JSONArray frames = obj.getJSONArray("http2_frames");
            assertNotNull(frames);
            String actual = null;
            for (int i = 0; i < frames.size(); i++) {
                JSONObject frame = frames.getJSONObject(i);
                if ("HEADERS".equals(frame.getString("name"))) {
                    actual = String.join(",", frame.getJSONArray("ordered_headers_key").toJavaList(String.class));
                    break;
                }
            }
            assertEquals(String.format("\nExpected :%s\nActual   :%s", orderedHeaders, actual),
                    orderedHeaders, actual);
        }
        String http2_digest = http2_fingerprint == null ? null : DigestUtils.md5Hex(http2_fingerprint);
        if (http2_digest != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", http2_fingerprint, obj.getString("http2_fingerprint")),
                    http2_digest, obj.getString("http2_digest"));
        }
        String headers_fp_digest = headers_fp == null ? null : DigestUtils.md5Hex(headers_fp);
        if (headers_fp_digest != null) {
            assertEquals(String.format("\n%s\n%s", headers_fp, obj.getString("headers_fp")),
                    headers_fp_digest, obj.getString("headers_fp_digest"));
        }
    }

    protected final void doTestBrowserScan(String ja4, String fp) throws Exception {
        JSONObject obj = doTestURL("https://tls.browserscan.net/api/tls");
        JSONObject tls = obj.getJSONObject("tls");
        assertNotNull(tls);
        if (fp != null) {
            String actual = normalizeBrowserScanSignatureAlgs(tls.getString("fp"));
            assertEquals(String.format("\nExpected :%s\nActual   :%s", fp, actual), fp, actual);
        }
        if (ja4 != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", ja4, tls.getString("ja4")),
                    ja4, tls.getString("ja4"));
        }
    }

    protected final void doTestPeetPrint(String ja4, String peetprint,
                                         String akamai_fingerprint,
                                         String ja3) throws Exception {
        doTestPeetPrint(ja4,
                peetprint == null ? null : DigestUtils.md5Hex(peetprint), peetprint,
                akamai_fingerprint == null ? null : DigestUtils.md5Hex(akamai_fingerprint), akamai_fingerprint,
                ja3 == null ? null : DigestUtils.md5Hex(ja3), ja3);
    }

    private void doTestPeetPrint(String ja4, String peetprint_hash, String peetprint,
                                         String akamai_fingerprint_hash, String akamai_fingerprint,
                                         String ja3_hash, String ja3) throws Exception {
        JSONObject obj = doTestURL("https://tls.peet.ws/api/all");
        JSONObject tls = obj.getJSONObject("tls");
        assertNotNull(tls);
        if(peetprint_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", peetprint, tls.getString("peetprint")),
                    peetprint_hash, tls.getString("peetprint_hash"));
        }
        if(ja3_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", ja3, tls.getString("ja3")),
                    ja3_hash, tls.getString("ja3_hash"));
        }
        if (ja4 != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", ja4, tls.getString("ja4")),
                    ja4, tls.getString("ja4"));
        }
        JSONObject http2 = obj.getJSONObject("http2");
        if(akamai_fingerprint_hash != null) {
            assertEquals(String.format("\nExpected :%s\nActual   :%s", akamai_fingerprint, http2.getString("akamai_fingerprint")),
                    akamai_fingerprint_hash, http2.getString("akamai_fingerprint_hash"));
        }
    }
}
