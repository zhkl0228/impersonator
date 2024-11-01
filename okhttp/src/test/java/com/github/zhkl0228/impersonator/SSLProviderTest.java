package com.github.zhkl0228.impersonator;

import com.alibaba.fastjson.JSON;
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

abstract class SSLProviderTest extends TestCase {

    protected abstract ImpersonatorApi createImpersonatorApi();

    protected final JSONObject doTestURL(String url) throws Exception {
        OkHttpClientFactory okHttpClientFactory = OkHttpClientFactory.create(createImpersonatorApi());
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

    protected void doTestBrowserLeaks(String ja3n_hash, String ja3n_text, String ja3_hash, String ja3_text,
                                      String userAgent,
                                      String akamai_hash, String akamai_text) throws Exception {
        JSONObject obj = doTestURL("https://tls.browserleaks.com/json");
        assertEquals(String.format("\n%s\n%s", ja3n_text, obj.getString("ja3n_text")),
                ja3n_hash, obj.getString("ja3n_hash"));
        if (ja3_hash != null) {
            assertEquals(String.format("\n%s\n%s", ja3_text, obj.getString("ja3_text")),
                    ja3_hash, obj.getString("ja3_hash"));
        }
        if (userAgent != null) {
            assertEquals(String.format("\n%s\n%s", userAgent, obj.getString("user_agent")), userAgent, obj.getString("user_agent"));
        }
        if (akamai_hash != null) {
            assertEquals(String.format("\n%s\n%s", akamai_text, obj.getString("akamai_text")),
                    akamai_hash, obj.getString("akamai_hash"));
        }
    }

    protected final void doTestScrapFlyJa3(String scrapfly_fp_digest, String scrapfly_fp) throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/fp/ja3");
        assertEquals(String.format("\n%s\n%s", scrapfly_fp, obj.getString("scrapfly_fp")),
                scrapfly_fp_digest, obj.getString("scrapfly_fp_digest"));
    }

    protected final void doTestScrapFlyHttp2(String http2_digest, String http2_fingerprint,
                                             String headers_fp_digest, String headers_fp) throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/http2");
        if (http2_digest != null) {
            assertEquals(String.format("\n%s\n%s", http2_fingerprint, obj.getString("http2_fingerprint")),
                    http2_digest, obj.getString("http2_digest"));
        }
        if (headers_fp_digest != null) {
            assertEquals(String.format("\n%s\n%s", headers_fp, obj.getString("headers_fp")),
                    headers_fp_digest, obj.getString("headers_fp_digest"));
        }
    }

    protected final void doTestBrowserScan(String ja4, String fp_hash, String fp) throws Exception {
        JSONObject obj = doTestURL("https://tls.browserscan.net/api/tls");
        JSONObject tls = obj.getJSONObject("tls");
        assertNotNull(tls);
        if(fp_hash != null) {
            assertEquals(String.format("\n%s\n%s", fp, tls.getString("fp")),
                    fp_hash, tls.getString("fp_hash"));
        }
        if (ja4 != null) {
            assertEquals(String.format("\n%s\n%s", ja4, tls.getString("ja4")),
                    ja4, tls.getString("ja4"));
        }
    }

    protected final void doTestPeetPrint(String ja4, String peetprint_hash, String peetprint,
                                         String akamai_fingerprint_hash, String akamai_fingerprint,
                                         String ja3_hash, String ja3) throws Exception {
        JSONObject obj = doTestURL("https://tls.peet.ws/api/all");
        JSONObject tls = obj.getJSONObject("tls");
        assertNotNull(tls);
        if(peetprint_hash != null) {
            assertEquals(String.format("\n%s\n%s", peetprint, tls.getString("peetprint")),
                    peetprint_hash, tls.getString("peetprint_hash"));
        }
        if(ja3_hash != null) {
            assertEquals(String.format("\n%s\n%s", ja3, tls.getString("ja3")),
                    ja3_hash, tls.getString("ja3_hash"));
        }
        if (ja4 != null) {
            assertEquals(String.format("\n%s\n%s", ja4, tls.getString("ja4")),
                    ja4, tls.getString("ja4"));
        }
        JSONObject http2 = obj.getJSONObject("http2");
        if(akamai_fingerprint_hash != null) {
            assertEquals(String.format("\n%s\n%s", akamai_fingerprint, http2.getString("akamai_fingerprint")),
                    akamai_fingerprint_hash, http2.getString("akamai_fingerprint_hash"));
        }
    }
}
