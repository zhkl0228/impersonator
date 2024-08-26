package com.github.zhkl0228.impersonator.other;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

abstract class OtherProviderTest extends TestCase implements X509TrustManager {

    private OkHttpClient buildHttpClient() throws Exception {
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(createSSLSocketFactory(), this);
        return builder.build();
    }

    protected final void doTestBrowserLeaks() throws Exception {
        doTestURL("https://tls.browserleaks.com/json");
    }

    protected final void doTestURL(String url) throws Exception {
        OkHttpClient client = buildHttpClient();
        Request request = new Request.Builder().url(url).build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            assertNotNull(body);
            String json = body.string();
            JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
        }
    }

    private SSLSocketFactory createSSLSocketFactory() throws Exception {
        return createSSLContext().getSocketFactory();
    }

    protected abstract SSLContext createSSLContext() throws Exception;

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
