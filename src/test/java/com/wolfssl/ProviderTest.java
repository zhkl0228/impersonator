package com.wolfssl;

import cn.hutool.core.net.DefaultTrustManager;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.parser.Feature;
import com.alibaba.fastjson.serializer.SerializerFeature;
import com.wolfssl.provider.jsse.WolfSSLProvider;
import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.scijava.nativelib.NativeLoader;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
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
        builder.sslSocketFactory(context.getSocketFactory(), trustManager);
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

}
