package okhttp3;

import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import org.bouncycastle.tls.TlsEchRejectedException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
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
        return newHttpClientInternal(null, null, null, socketFactory, null);
    }

    @Override
    public OkHttpClient newHttpClient(String userAgent) {
        return newHttpClientInternal(null, null, userAgent, null, null);
    }

    @Override
    public OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent) {
        return newHttpClientInternal(km, tm, userAgent, null, null);
    }

    @Override
    public OkHttpClient newHttpClient(Dns dns) {
        return newHttpClientInternal(null, null, null, null, dns);
    }

    private OkHttpClient newHttpClientInternal(KeyManager[] km, TrustManager[] tm, String userAgent, SocketFactory socketFactory, Dns dns) {
        OkHttpClient.Builder builder = okHttpClientBuilderFactory == null ? new OkHttpClient.Builder() : okHttpClientBuilderFactory.newOkHttpClientBuilder();
        applyTimeouts(builder);
        X509TrustManager trustManager = getX509TrustManager(tm);
        if (socketFactory != null) {
            builder.socketFactory(new OkHttpClientSocketFactory(socketFactory));
        }
        if (dns != null) {
            builder.dns(dns);
        }
        builder.sslSocketFactory(api.newSSLContext(km, new TrustManager[]{trustManager}).getSocketFactory(), trustManager);
        // Outermost, so that a retried request goes through the interceptors below it again.
        builder.addInterceptor(new EchRetryInterceptor());
        builder.addInterceptor(new ImpersonatorInterceptor(userAgent == null ? api.getUserAgent() : userAgent));
        // Only acts when a profile sent its own Accept-Encoding; otherwise okhttp already handled it.
        builder.addInterceptor(DecompressionInterceptor.DEFAULT);
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

    /**
     * RFC 9849 section 6.1.6. A server that rejects Encrypted Client Hello publishes the config it
     * wants instead, so remember it and go back once. A browser does the same; without this the
     * caller is handed an exception carrying configs it has no way to feed back in.
     */
    private class EchRetryInterceptor implements Interceptor {
        /**
         * Caught directly rather than off a cause chain: nothing between the handshake and here
         * wraps it. ProvSSLSocketWrap.startHandshake has no catch at all, ConnectPlan only catches
         * SSLException, and the route finders and RetryAndFollowUpInterceptor attach the failures
         * they collect with addSuppressed and rethrow the original.
         */
        @NotNull
        @Override
        public Response intercept(@NotNull Chain chain) throws IOException {
            Request request = chain.request();
            try {
                return chain.proceed(request);
            } catch (TlsEchRejectedException e) {
                RequestBody body = request.body();
                if (body != null && body.isOneShot()) {
                    // The handshake fails before the body is written, but there is nothing to gain
                    // from finding out the hard way that it cannot be written twice.
                    throw e;
                }
                log.debug("ech rejected by {} as {}, retrying with its retry_configs",
                        request.url().host(), e.getPublicName());
                try {
                    api.onEchRejected(request.url().host(), e.getRetryConfigs());
                } catch (IOException unusable) {
                    /*
                     * The server offered nothing we can use, so there is nothing to go back with.
                     * The rejection is what the caller catches for, so that is what it gets; why the
                     * retry never happened rides along suppressed.
                     */
                    e.addSuppressed(unusable);
                    throw e;
                }
                // Deliberately not wrapped: exactly one retry, so a server that keeps rejecting is
                // reported rather than looped on.
                return chain.proceed(request);
            }
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

    /**
     * okhttp needs the trust manager itself, not just the socket factory, because it builds the
     * chain cleaner used for certificate pinning from it. Naming none gets the platform's root
     * store, the same thing okhttp would use on its own.
     */
    private static X509TrustManager getX509TrustManager(TrustManager[] tm) {
        if (tm == null || tm.length == 0) {
            return ImpersonatorFactory.DEFAULT_TRUST_MANAGER;
        }
        for (TrustManager trustManager : tm) {
            if (trustManager instanceof X509TrustManager) {
                return (X509TrustManager) trustManager;
            }
        }
        throw new IllegalArgumentException("no X509TrustManager among " + Arrays.toString(tm));
    }
}
