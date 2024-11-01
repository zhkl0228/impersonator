package okhttp3;

import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.LinkedHashMap;
import java.util.Map;

class DefaultHttpClientFactory extends OkHttpClientFactory {

    private static final Logger log = LoggerFactory.getLogger(DefaultHttpClientFactory.class);

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
        return newHttpClient((String) null);
    }

    @Override
    public OkHttpClient newHttpClient(SocketFactory socketFactory) {
        return newHttpClientInternal(null, new TrustManager[]{
                new ImpersonatorFactory.DummyX509KeyManager()
        }, null, socketFactory);
    }

    @Override
    public OkHttpClient newHttpClient(String userAgent) {
        return newHttpClient(null, new TrustManager[]{
                new ImpersonatorFactory.DummyX509KeyManager()
        }, userAgent);
    }

    @Override
    public OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent) {
        return newHttpClientInternal(km, tm, userAgent, null);
    }

    private OkHttpClient newHttpClientInternal(KeyManager[] km, TrustManager[] tm, String userAgent, SocketFactory socketFactory) {
        OkHttpClient.Builder builder = okHttpClientBuilderFactory == null ? new OkHttpClient.Builder() : okHttpClientBuilderFactory.newOkHttpClientBuilder();
        X509TrustManager trustManager = getX509KeyManager(tm);
        if (socketFactory != null) {
            builder.socketFactory(new OkHttpClientSocketFactory(socketFactory));
        }
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

    private static class OkHttpClientSocketFactory extends javax.net.SocketFactory {
        private final SocketFactory socketFactory;
        OkHttpClientSocketFactory(SocketFactory socketFactory) {
            this.socketFactory = socketFactory;
        }
        @Override
        public Socket createSocket() throws IOException {
            return socketFactory.newSocket();
        }
        @Override
        public Socket createSocket(String host, int port) {
            throw new UnsupportedOperationException();
        }
        @Override
        public Socket createSocket(String host, int port, InetAddress localHost, int localPort) {
            throw new UnsupportedOperationException();
        }
        @Override
        public Socket createSocket(InetAddress host, int port) {
            throw new UnsupportedOperationException();
        }
        @Override
        public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) {
            throw new UnsupportedOperationException();
        }
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
            Map<String, String> headers = new LinkedHashMap<>();
            Headers requestHeaders = request.headers();
            for (String name : requestHeaders.names()) {
                String value = requestHeaders.get(name);
                log.debug("intercept name={} value={}", name, value);
                builder.removeHeader(name);
                headers.put(name, value);
            }
            if (userAgent != null) {
                headers.put("User-Agent", userAgent);
            }
            onInterceptRequest(builder, headers);
            return chain.proceed(builder.build());
        }
    }

    private void onInterceptRequest(Request.Builder builder, Map<String, String> headers) {
        api.fillRequestHeaders(headers);
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            builder.header(entry.getKey(), entry.getValue());
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
