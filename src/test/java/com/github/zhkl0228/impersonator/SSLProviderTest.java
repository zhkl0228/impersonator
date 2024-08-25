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

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public abstract class SSLProviderTest extends TestCase implements X509TrustManager {

    protected OkHttpClient client;

    @Override
    protected void setUp() throws Exception {
        super.setUp();

        client = buildHttpClient();
    }

    @Override
    protected void tearDown() throws Exception {
        super.tearDown();

        client = null;
    }

    private OkHttpClient buildHttpClient() throws Exception {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(createSSLSocketFactory(), this);
        return builder.build();
    }

    protected final JSONObject doTestBrowserLeaks() throws Exception {
        return doTestURL("https://tls.browserleaks.com/json");
    }

    protected final JSONObject doTestURL(String url) throws Exception {
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

    protected void doTestBrowserLeaks(String ja3n_hash, String ja3n_text, String ja3_hash, String ja3_text) throws Exception {
        JSONObject obj = doTestBrowserLeaks();
        assertEquals(String.format("\n%s\n%s", ja3n_text, obj.getString("ja3n_text")),
                ja3n_hash, obj.getString("ja3n_hash"));
        if (ja3_hash != null) {
            assertEquals(String.format("\n%s\n%s", ja3_text, obj.getString("ja3_text")),
                    ja3_hash, obj.getString("ja3_hash"));
        }
    }

    protected final void doTestScrapFlyJa3(String scrapfly_fp_digest, String scrapfly_fp) throws Exception {
        JSONObject obj = doTestURL("https://tools.scrapfly.io/api/fp/ja3");
        assertEquals(String.format("\n%s\n%s", scrapfly_fp, obj.getString("scrapfly_fp")),
                scrapfly_fp_digest, obj.getString("scrapfly_fp_digest"));
    }

    protected abstract SSLSocketFactory createSSLSocketFactory() throws Exception;

    @Override
    public final void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    @Override
    public final void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    @Override
    public final X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
