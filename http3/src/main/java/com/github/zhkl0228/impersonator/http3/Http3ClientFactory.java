package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.EchConfigProvider;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.QuicClientHello;
import com.github.zhkl0228.impersonator.QuicTransport;
import com.github.zhkl0228.impersonator.quic.EchRejectionHandler;
import com.github.zhkl0228.impersonator.quic.QuicClientFactory;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
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
    private final Map<Long, Long> http3Settings;

    private Duration connectTimeout = Duration.ofSeconds(10);

    private final Impersonator impersonator;

    /**
     * Whether the impersonated browser does Encrypted Client Hello. True when there is no profile
     * behind this factory, a bare ClientHello spec having no opinion about it.
     */
    private final boolean echSupported;

    private Http3ClientFactory(QuicClientFactory quicClientFactory, Map<Long, Long> http3Settings,
                               Impersonator impersonator, boolean echSupported) {
        this.quicClientFactory = quicClientFactory;
        this.http3Settings = http3Settings;
        this.impersonator = impersonator;
        this.echSupported = echSupported;
    }

    /**
     * @param api a profile from {@link ImpersonatorFactory}.
     * @throws UnsupportedOperationException if no capture of this browser over HTTP/3 has been taken;
     *             see {@link Impersonator#getQuicClientHello()}. A browser's QUIC ClientHello is not
     *             its TCP one, and this library does not invent one from the other.
     */
    public static Http3ClientFactory create(ImpersonatorApi api) {
        Impersonator impersonator = api instanceof Impersonator? (Impersonator) api: null;
        return new Http3ClientFactory(QuicClientFactory.create(api),
                impersonator == null? null: impersonator.getHttp3Settings(),
                impersonator, api.isEchSupported());
    }

    /**
     * A ClientHello on its own, with no profile behind it. For a capture of something that is not one
     * of this library's browsers.
     */
    public static Http3ClientFactory create(QuicClientHello quicClientHello) {
        return create(quicClientHello, null);
    }

    /** A ClientHello and the QUIC layer that goes with it, with no profile behind them. */
    public static Http3ClientFactory create(QuicClientHello quicClientHello, QuicTransport quicTransport) {
        return new Http3ClientFactory(QuicClientFactory.create(quicClientHello, quicTransport), null, null, true);
    }

    /**
     * Clients that impersonate nothing: agent15's own ClientHello and no Encrypted Client Hello.
     * Useful as the control in a fingerprint comparison, and for plain HTTP/3.
     */
    public static Http3ClientFactory create() {
        return new Http3ClientFactory(QuicClientFactory.create(), null, null, true);
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
        if (!echSupported && echConfigProvider != null) {
            /*
             * The same refusal the TCP path makes, for the same reason: offering a real Encrypted
             * Client Hello would put an extension in the ClientHello that this browser never sends -
             * Safari sends none - so the connection would be less like the browser, not more. Ask
             * ImpersonatorApi.isEchSupported() rather than keeping a list of which profiles do.
             */
            throw new UnsupportedOperationException("this profile impersonates a browser that does not"
                    + " support Encrypted Client Hello");
        }
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
        return new Http3Client(quicClientFactory, http3Settings, connectTimeout, impersonator);
    }

}
