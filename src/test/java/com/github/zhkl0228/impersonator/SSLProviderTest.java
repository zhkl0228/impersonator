package com.github.zhkl0228.impersonator;

import cn.hutool.core.net.DefaultTrustManager;
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

public abstract class SSLProviderTest extends TestCase {

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
        X509TrustManager trustManager = new DefaultTrustManager();
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(createSSLSocketFactory(), trustManager);
        return builder.build();
    }

    protected final void doTestBrowserLeaks() throws Exception {
        Request request = new Request.Builder().url("https://tls.browserleaks.com/json").build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            assertNotNull(body);
            String json = body.string();
            JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
        }
    }

    protected abstract SSLSocketFactory createSSLSocketFactory() throws Exception;

}
