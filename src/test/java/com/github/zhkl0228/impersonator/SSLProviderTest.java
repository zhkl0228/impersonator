package com.github.zhkl0228.impersonator;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

abstract class SSLProviderTest extends TestCase {

    protected final JSONObject doTestBrowserLeaks() throws Exception {
        return doTestURL("https://tls.browserleaks.com/json");
    }

    protected abstract ImpersonatorApi createImpersonatorApi();

    protected final JSONObject doTestURL(String url) throws Exception {
        OkHttpClient client = createImpersonatorApi().newHttpClient();
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
        JSONObject obj = doTestBrowserLeaks();
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
}
