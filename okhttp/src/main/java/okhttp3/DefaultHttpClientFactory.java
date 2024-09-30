package okhttp3;

import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import org.jetbrains.annotations.NotNull;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

class DefaultHttpClientFactory extends OkHttpClientFactory {

    private final ImpersonatorFactory api;
    private final OkHttpClientBuilderFactory okHttpClientBuilderFactory;

    public DefaultHttpClientFactory(ImpersonatorApi api, OkHttpClientBuilderFactory okHttpClientBuilderFactory) {
        super();
        if (!(api instanceof ImpersonatorFactory)) {
            throw new UnsupportedOperationException("Only ImpersonatorFactory instances are supported");
        }
        this.api = (ImpersonatorFactory) api;
        this.okHttpClientBuilderFactory = okHttpClientBuilderFactory;
    }

    @Override
    public OkHttpClient newHttpClient() {
        return newHttpClient(null);
    }

    @Override
    public OkHttpClient newHttpClient(String userAgent) {
        return newHttpClient(null, new TrustManager[]{
                new ImpersonatorFactory.DummyX509KeyManager()
        }, userAgent);
    }

    @Override
    public OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent) {
        OkHttpClient.Builder builder = okHttpClientBuilderFactory == null ? new OkHttpClient.Builder() : okHttpClientBuilderFactory.newOkHttpClientBuilder();
        X509TrustManager trustManager = getX509KeyManager(tm);
        builder.sslSocketFactory(api.newSSLContext(km, new TrustManager[]{trustManager}).getSocketFactory(), trustManager);
        builder.addInterceptor(new ImpersonatorInterceptor(userAgent == null ? api.getUserAgent() : userAgent));
        builder.eventListener(new EventListener() {
            @Override
            public void onHttp2ConnectionInit(@NotNull Http2Connection http2Connection) {
                api.onHttp2ConnectionInit(http2Connection);
            }
        });
        return builder.build();
    }

    private class ImpersonatorInterceptor implements Interceptor {
        private final String userAgent;

        ImpersonatorInterceptor(String userAgent) {
            this.userAgent = userAgent;
        }

        @NotNull
        @Override
        public Response intercept(@NotNull Chain chain) throws IOException {
            Request request = chain.request();
            Request.Builder builder = request.newBuilder();
            if (userAgent != null) {
                addHeader(request, builder, "User-Agent", userAgent);
            }
            onInterceptRequest(request, builder);
            return chain.proceed(builder.build());
        }
    }

    private void onInterceptRequest(Request request, Request.Builder builder) {
        Map<String, String> headers = new LinkedHashMap<>();
        api.fillRequestHeaders(headers);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            addHeader(request, builder, entry.getKey(), entry.getValue());
        }
    }

    private void addHeader(Request request, Request.Builder builder, String name, String value) {
        if (request.header(name) == null) {
            builder.header(name, value);
        }
    }

    private static X509TrustManager getX509KeyManager(TrustManager[] tm) {
        X509TrustManager trustManager;
        if (tm != null && tm.length > 0) {
            trustManager = (X509TrustManager) tm[0];
        } else {
            trustManager = new ImpersonatorFactory.DummyX509KeyManager();
        }
        return trustManager;
    }
}
