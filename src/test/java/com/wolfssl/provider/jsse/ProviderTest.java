package com.wolfssl.provider.jsse;

import cn.hutool.core.net.DefaultTrustManager;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;
import com.wolfssl.WolfSSLException;
import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.scijava.nativelib.NativeLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.security.Security;

public class ProviderTest extends TestCase {

    static {
        try {
            NativeLoader.loadLibrary("wolfssljni");
            Security.addProvider(new WolfSSLProvider());
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }
    }

    public void testSSLContext() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
        assertNotNull(context);
    }

    public void testHttp() throws Exception {
        SSLContext context = SSLContext.getInstance("TLSv1.3", "wolfJSSE");
        assertNotNull(context);
        X509TrustManager trustManager = new DefaultTrustManager();
        context.init(null, new TrustManager[]{trustManager}, null);
        OkHttpClient.Builder builder = new OkHttpClient.Builder();
        builder.sslSocketFactory(createSSLSocketFactory(), trustManager);
        OkHttpClient client = builder.build();
        Request request = new Request.Builder().url("https://tls.browserleaks.com/json").build();
        try (Response response = client.newCall(request).execute()) {
            ResponseBody body = response.body();
            assertNotNull(body);
            String json = body.string();
            JSONObject obj = JSON.parseObject(json, Feature.OrderedField);
            System.out.println(obj.toString(SerializerFeature.PrettyFormat));
        }
    }

    private SSLSocketFactory createSSLSocketFactory() throws WolfSSLException, KeyManagementException {
        com.wolfssl.WolfSSLContext context = new WolfSSLContext(WolfSSL.TLSv1_3_Method());
        context.setCipherList("TLS_AES_128_GCM_SHA256");
//        context.set1SigAlgsList("RSA+SHA256:ECDSA:SHA256");
        WolfSSLAuthStore authStore = new WolfSSLAuthStore(null, new TrustManager[]{new DefaultTrustManager()}, new SecureRandom(), WolfSSL.TLS_VERSION.TLSv1_3);
        WolfSSLParameters parameters = new WolfSSLParameters();
        parameters.setProtocols(new String[]{"TLSv1.3", "TLSv1.2"});
        parameters.setCipherSuites(new String[]{"TLS_AES_128_GCM_SHA256"});
        return new WolfSSLSocketFactory(context, authStore, parameters);
    }

}
