package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.EchConfigProvider;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.QuicClientHello;
import com.github.zhkl0228.impersonator.quic.EchRejectionHandler;
import com.github.zhkl0228.impersonator.quic.QuicClientFactory;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Builds HTTP/3 clients that impersonate a browser, the way {@code OkHttpClientFactory} builds
 * HTTP/2 ones.
 *
 * <pre>
 * ImpersonatorApi api = ImpersonatorFactory.macChrome();
 * HttpClient client = Http3ClientFactory.create(api).newHttpClient();
 *
 * HttpResponse&lt;String&gt; response = client.send(
 *         HttpRequest.newBuilder(URI.create("https://cloudflare-ech.com/cdn-cgi/trace")).build(),
 *         HttpResponse.BodyHandlers.ofString());
 * </pre>
 *
 * Encrypted Client Hello is on by default for a profile whose browser does it, resolving the host's
 * ECHConfigList over DNS-over-HTTPS exactly as the TCP path does.
 * <p>
 * The client returned holds one QUIC connection per host and port, opened on first use. Nothing is
 * process wide: two clients from two factories impersonate two different browsers side by side.
 */
public class Http3ClientFactory {

    private final QuicClientFactory quicClientFactory;

    private Duration connectTimeout = Duration.ofSeconds(10);

    private Http3ClientFactory(QuicClientFactory quicClientFactory) {
        this.quicClientFactory = quicClientFactory;
    }

    /**
     * @param api a profile from {@link ImpersonatorFactory}.
     * @throws UnsupportedOperationException if no capture of this browser over HTTP/3 has been taken;
     *             see {@link Impersonator#getQuicClientHello()}. A browser's QUIC ClientHello is not
     *             its TCP one, and this library does not invent one from the other.
     */
    public static Http3ClientFactory create(ImpersonatorApi api) {
        return new Http3ClientFactory(QuicClientFactory.create(api));
    }

    /**
     * A ClientHello on its own, with no profile behind it. For a capture of something that is not one
     * of this library's browsers.
     */
    public static Http3ClientFactory create(QuicClientHello quicClientHello) {
        return new Http3ClientFactory(QuicClientFactory.create(quicClientHello));
    }

    /**
     * Clients that impersonate nothing: agent15's own ClientHello and no Encrypted Client Hello.
     * Useful as the control in a fingerprint comparison, and for plain HTTP/3.
     */
    public static Http3ClientFactory create() {
        return new Http3ClientFactory(QuicClientFactory.create());
    }

    /** How long {@link HttpClient#send} waits for the QUIC handshake. Defaults to 10 seconds. */
    public Http3ClientFactory setConnectTimeout(long timeout, TimeUnit unit) {
        this.connectTimeout = Duration.ofMillis(unit.toMillis(timeout));
        return this;
    }

    /**
     * Replaces the profile's own source of ECHConfigLists, which is the DNS-over-HTTPS lookup a
     * browser does. Null turns Encrypted Client Hello off.
     */
    public Http3ClientFactory setEchConfigProvider(EchConfigProvider echConfigProvider) {
        quicClientFactory.setEchConfigProvider(echConfigProvider);
        return this;
    }

    /**
     * Called when a server rejects the ECHConfig that was offered, with the {@code retry_configs} it
     * published. Retrying is left to the caller; see {@link EchRejectionHandler}.
     */
    public Http3ClientFactory setEchRejectionHandler(EchRejectionHandler echRejectionHandler) {
        quicClientFactory.setEchRejectionHandler(echRejectionHandler);
        return this;
    }

    /**
     * @return a client whose connections carry this factory's profile. It owns QUIC connections, so
     *         close it when done; {@link HttpClient} is {@link AutoCloseable}, which is the reason
     *         this module is Java 21 while the ones below it are Java 11.
     */
    public HttpClient newHttpClient() {
        return new Http3Client(quicClientFactory, connectTimeout);
    }

}
