package okhttp3;

import com.github.zhkl0228.impersonator.ImpersonatorApi;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

public abstract class OkHttpClientFactory {

    private Duration connectTimeout;
    private Duration readTimeout;
    private Duration writeTimeout;
    private Duration callTimeout;

    /**
     * Applies the timeouts set here to a builder, leaving okhttp's own defaults in place for the
     * ones that were never set.
     */
    protected final void applyTimeouts(OkHttpClient.Builder builder) {
        if (connectTimeout != null) {
            builder.connectTimeout(connectTimeout);
        }
        if (readTimeout != null) {
            builder.readTimeout(readTimeout);
        }
        if (writeTimeout != null) {
            builder.writeTimeout(writeTimeout);
        }
        if (callTimeout != null) {
            builder.callTimeout(callTimeout);
        }
    }

    /** Timeout for establishing the TCP connection. okhttp defaults to 10 seconds. */
    public OkHttpClientFactory setConnectTimeout(long timeout, TimeUnit unit) {
        this.connectTimeout = Duration.ofNanos(unit.toNanos(timeout));
        return this;
    }

    /** Timeout between two bytes read from the server. okhttp defaults to 10 seconds. */
    public OkHttpClientFactory setReadTimeout(long timeout, TimeUnit unit) {
        this.readTimeout = Duration.ofNanos(unit.toNanos(timeout));
        return this;
    }

    /** Timeout between two bytes written to the server. okhttp defaults to 10 seconds. */
    public OkHttpClientFactory setWriteTimeout(long timeout, TimeUnit unit) {
        this.writeTimeout = Duration.ofNanos(unit.toNanos(timeout));
        return this;
    }

    /**
     * Timeout for a complete call, DNS, connect, redirects and the whole body included. okhttp
     * applies no such limit by default.
     */
    public OkHttpClientFactory setCallTimeout(long timeout, TimeUnit unit) {
        this.callTimeout = Duration.ofNanos(unit.toNanos(timeout));
        return this;
    }

    public static OkHttpClientFactory create(ImpersonatorApi api) {
        return create(api, null);
    }

    public static OkHttpClientFactory create(ImpersonatorApi api, OkHttpClientBuilderFactory okHttpClientBuilderFactory) {
        return new DefaultHttpClientFactory(api, okHttpClientBuilderFactory);
    }

    public abstract OkHttpClient newHttpClient();

    public abstract OkHttpClient newHttpClient(SocketFactory socketFactory);

    public abstract OkHttpClient newHttpClient(String userAgent);

    public abstract OkHttpClient newHttpClient(KeyManager[] km, TrustManager[] tm, String userAgent);

    public abstract OkHttpClient newHttpClient(Dns dns);

}
