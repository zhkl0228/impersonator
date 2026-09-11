package com.github.zhkl0228.impersonator.http3.core;

import com.github.zhkl0228.impersonator.EchConfigProvider;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.QuicClientHello;
import com.github.zhkl0228.impersonator.QuicTransport;
import com.github.zhkl0228.impersonator.quic.NewTokenStore;
import com.github.zhkl0228.impersonator.quic.QuicClientFactory;
import com.github.zhkl0228.impersonator.quic.SessionTicketStore;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.concurrent.DaemonThreadFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Opens HTTP/3 connections that impersonate a browser - everything about them, not only the
 * handshake.
 * <p>
 * A connection from here carries the profile's QUIC transport parameters and its TLS ClientHello,
 * resumes with the browser's resumed ClientHello when it has a ticket, offers the address validation
 * token it was given last time, sends the browser's HTTP/3 SETTINGS and means them, puts the field
 * lines of every request in the browser's order, and adds the headers the browser adds. A caller that
 * uses {@link tech.kwik.flupke.Http3ClientConnection}'s own API gets all of that without doing
 * anything about it:
 *
 * <pre>
 * Http3ConnectionFactory factory = Http3ConnectionFactory.create(ImpersonatorFactory.macChrome());
 * try (Http3Connection connection = factory.newConnection(URI.create("https://example.com"))) {
 *     HttpResponse&lt;String&gt; response = connection.send(
 *             HttpRequest.newBuilder(URI.create("https://example.com")).build(),
 *             HttpResponse.BodyHandlers.ofString());
 * }
 * </pre>
 *
 * {@code impersonator-http3} is the same thing behind {@link java.net.http.HttpClient}, with a
 * connection per host kept for you; it needs a Java 21 because that is where that class became
 * {@link AutoCloseable}. This needs only the Java 11 the QUIC modules are built for.
 * <p>
 * One connection per call, and closing it is the caller's business. What it learns on the way - the
 * session tickets and the address validation tokens the server hands out - reaches this factory's
 * stores as each one arrives, so the next connection has it whether or not this one was closed
 * tidily. What the server had not sent by the time the caller closed is another matter, and only
 * staying connected longer answers it.
 */
public class Http3ConnectionFactory {

    private final QuicClientFactory quicClientFactory;
    private final Impersonator impersonator;

    /** The order the profile's field lines go on the wire; null when it declares none. */
    private final List<String> fieldOrder;

    /** The headers it adds to every request, in the order it adds them; empty when there is none. */
    private final Map<String, String> profileHeaders;

    private Duration connectTimeout = Duration.ofSeconds(10);

    /** Daemon threads, so a connection nobody closed cannot keep the JVM alive. */
    private final ExecutorService executorService =
            Executors.newCachedThreadPool(new DaemonThreadFactory("impersonator-http3"));

    private Http3ConnectionFactory(QuicClientFactory quicClientFactory, Impersonator impersonator) {
        this.quicClientFactory = quicClientFactory;
        this.impersonator = impersonator;
        this.profileHeaders = impersonator == null
                ? Collections.emptyMap()
                : Collections.unmodifiableMap(profileHeaders(impersonator));
        this.fieldOrder = impersonator == null ? null
                : FieldSectionOrder.of(impersonator.getPseudoHeaderOrder(), profileHeaders.keySet());
    }

    /**
     * @param api a profile from {@link ImpersonatorFactory}.
     * @throws UnsupportedOperationException if no capture of this browser over HTTP/3 has been taken;
     *             see {@link Impersonator#getQuicClientHello()}. A browser's QUIC ClientHello is not
     *             its TCP one, and this library does not invent one from the other.
     */
    public static Http3ConnectionFactory create(ImpersonatorApi api) {
        Impersonator impersonator = api instanceof Impersonator ? (Impersonator) api : null;
        return new Http3ConnectionFactory(QuicClientFactory.create(api), impersonator);
    }

    /** A ClientHello and the QUIC layer that goes with it, with no profile behind them. */
    public static Http3ConnectionFactory create(QuicClientHello quicClientHello, QuicTransport quicTransport) {
        return new Http3ConnectionFactory(QuicClientFactory.create(quicClientHello, quicTransport), null);
    }

    /** Connections that impersonate nothing, for use as the control in a comparison. */
    public static Http3ConnectionFactory create() {
        return new Http3ConnectionFactory(QuicClientFactory.create(), null);
    }

    /**
     * The QUIC layer of this factory: where the session ticket and address validation token stores
     * live, and where Encrypted Client Hello is configured. See {@link QuicClientFactory}.
     */
    public QuicClientFactory getQuicClientFactory() {
        return quicClientFactory;
    }

    /** How long a connection may take to hand shake. Ten seconds by default. */
    public Http3ConnectionFactory setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = Objects.requireNonNull(connectTimeout);
        return this;
    }

    /** See {@link #setConnectTimeout(Duration)}. */
    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    /**
     * The threads the connections from this factory run their callbacks on - reading the peer's
     * control, QPACK and response streams. Cached and daemon, so connections nobody closed cannot keep
     * the JVM alive, and idle threads go away on their own.
     */
    public ExecutorService getExecutor() {
        return executorService;
    }

    /** Replaces the profile's source of ECHConfigLists; see {@link QuicClientFactory#setEchConfigProvider}. */
    public Http3ConnectionFactory setEchConfigProvider(EchConfigProvider echConfigProvider) {
        quicClientFactory.setEchConfigProvider(echConfigProvider);
        return this;
    }

    /**
     * Opens one, connected and with its HTTP/3 streams open, ready to take a request.
     * <p>
     * The QUIC connection is brought up here rather than lazily, because a handshake failure belongs
     * to the call that caused it rather than to the first request that happens to follow.
     *
     * @param uri anything with a host; its port, or 443, is what is connected to
     */
    public Http3Connection newConnection(URI uri) throws IOException {
        return newConnection(uri, builder -> {});
    }

    /**
     * The same, with the QUIC connection settings this factory has no opinion about.
     * <p>
     * The builder handed to {@code connectionSettings} is one this factory made, so the profile is
     * already on it - the ClientHello spec, the transport parameters, the connection id lengths, the
     * Initial packet layout - and so is everything HTTP/3 needs: the "h3" protocol, the address, the
     * connect timeout, and the session ticket and address validation token kept from the last
     * connection to this host. What is left is what belongs to the caller and not to the browser:
     *
     * <pre>
     * factory.newConnection(uri, builder -&gt; builder
     *         .noServerCertificateCheck()          // a server whose certificate is pinned elsewhere
     *         .proxy(address)                      // dial this address, keep the URI's name in the SNI
     *         .maxIdleTimeout(Duration.ofSeconds(30))
     *         .enableDatagramExtension());         // RFC 9221, which a UDP relay over QUIC needs
     * </pre>
     *
     * It runs last, so a caller that sets something this factory also sets wins. That is deliberate
     * and is worth knowing about the two that carry the fingerprint: replacing what a profile put on
     * the builder makes the connection less like the browser, not more.
     *
     * @param connectionSettings called with the builder, after this factory has configured it and
     *                           before it is built
     */
    public Http3Connection newConnection(URI uri, Consumer<QuicClientConnection.Builder> connectionSettings)
            throws IOException {
        String host = Objects.requireNonNull(uri.getHost(), () -> "no host in " + uri);

        /*
         * A ticket kept from an earlier connection to this host turns the handshake into a resumed
         * one: the ClientHello carries "pre_shared_key" and "early_data" and is a different message
         * with a different JA4, which is what a browser's second visit to a host looks like. Without
         * this every connection is a full handshake for ever, which no browser's history contains.
         *
         * Only for a profile that can describe a resumed ClientHello; see
         * Impersonator.isQuicSessionResumptionSupported. Without a profile at all there is no
         * dictated ClientHello to accommodate, and the engine builds its own.
         */
        boolean mayResume = impersonator == null || impersonator.isQuicSessionResumptionSupported();
        SessionTicketStore sessionTicketStore = quicClientFactory.getSessionTicketStore();
        QuicSessionTicket ticket = sessionTicketStore == null || !mayResume
                ? null
                : sessionTicketStore.take(host);

        /*
         * And the address validation token from an earlier connection to this host, which is a
         * separate thing from the ticket and answers a separate question: the ticket says who the
         * client is to TLS, the token says the server has seen this address before. Without one a
         * server under load answers with a Retry, so a client that keeps none takes an extra round
         * trip on every connection where a browser takes one only on its first.
         */
        NewTokenStore newTokenStore = quicClientFactory.getNewTokenStore();
        byte[] token = newTokenStore == null ? null : newTokenStore.take(host);

        QuicClientConnection.Builder builder = quicClientFactory.newBuilder()
                .uri(uri)
                .port(uri.getPort() == -1 ? 443 : uri.getPort())
                .applicationProtocol("h3")
                .connectTimeout(connectTimeout)
                .sessionTicket(ticket)
                .initialToken(token);
        connectionSettings.accept(builder);
        QuicClientConnection quicConnection = builder.build();

        // Asked per connection and not once per factory: a profile's SETTINGS frame carries a GREASE
        // setting whose identifier and value are drawn afresh each time it is asked, and one drawn
        // once per factory would be the same on every connection this factory opens - a stable
        // identifier rather than noise, which is the opposite of what GREASE is for.
        Map<Long, Long> http3Settings = impersonator == null ? null : impersonator.getHttp3Settings();

        // Constructed before the QUIC connection is up, because the constructor is what registers
        // the callback for peer-initiated streams and kwik drops any that arrive before there is
        // one - silently, its default being a no-op consumer. The server opens its control and QPACK
        // encoder streams as soon as the handshake completes, so connecting first loses whichever of
        // them wins the race, and the QPACK one carries the dynamic table.
        Http3Connection connection = new Http3Connection(quicConnection, executorService, http3Settings,
                fieldOrder, profileHeaders);

        /*
         * As they arrive, not when this connection is closed. Collecting at close made the stores
         * depend on close being called and on its timing: a connection that is kept - which is what
         * the HttpClient above does, one per host for as long as it lives - had everything the server
         * handed it sitting where nothing else could reach it, and one that was dropped rather than
         * closed taught this factory nothing at all.
         *
         * It does not conjure what has not arrived. A server that sends its NewSessionTicket after the
         * response has sent nothing by the time a caller that closes at once has closed; keeping a
         * connection open is the only thing that helps there, and that is the caller's to decide.
         *
         * Registered before the handshake starts, so nothing can arrive before there is somewhere to
         * put it. The listener runs on the thread that processed the packet and must not throw: a
         * ticket that cannot be kept costs the next connection a full handshake, and a token a Retry,
         * and neither is worth ending a working connection over.
         */
        if (sessionTicketStore != null) {
            quicConnection.onNewSessionTicket(newTicket -> {
                try {
                    sessionTicketStore.put(host, Collections.singletonList(newTicket));
                }
                catch (RuntimeException ignored) {
                }
            });
        }
        if (newTokenStore != null) {
            quicConnection.onNewToken(newToken -> {
                try {
                    newTokenStore.put(host, Collections.singletonList(newToken));
                }
                catch (RuntimeException ignored) {
                }
            });
        }
        try {
            if (ticket != null) {
                /*
                 * Resuming, so the handshake is started and not waited for: what follows - this
                 * connection's control stream, its SETTINGS, its QPACK decoder stream, and then the
                 * request itself, which flupke writes on a stream it opens for itself - happens inside
                 * the 0-RTT window and goes out in the first flight. Nothing below this line knows that;
                 * see QuicClientConnection.startConnect.
                 *
                 * Waiting for the handshake is the connection's own, at the first moment anything is
                 * expected back from the peer. Offering "early_data" and sending nothing would be a claim
                 * about this client that is not true, and is refused there.
                 */
                quicConnection.startConnect(true);
            }
            else {
                quicConnection.connect();
            }
            connection.connect();
        }
        catch (IOException | RuntimeException failed) {
            /*
             * Nothing is handed back, so nothing can be closed by the caller, so it is closed here.
             * The window where this matters is real: the QUIC handshake can succeed and the HTTP/3
             * streams opened right after it can fail, because the peer closed the connection in
             * between - and then a connected QUIC connection, its socket and its threads were left
             * with no reference to them anywhere.
             */
            try {
                connection.close();
            }
            catch (RuntimeException ignored) {
                // The failure being reported is the one worth reporting.
            }
            throw failed;
        }
        return connection;
    }

    /**
     * The headers a profile adds to every request, in the order it adds them.
     * <p>
     * The User-Agent is seeded first because a profile moves that header rather than supplying it:
     * Chrome takes it back out and puts it after Upgrade-Insecure-Requests, which it can only do to a
     * header already in the map. So this map's iteration order is the browser's field order, and it
     * is the only place that order exists.
     */
    private static Map<String, String> profileHeaders(Impersonator impersonator) {
        Map<String, String> headers = new LinkedHashMap<>();
        String userAgent = impersonator.getUserAgent();
        if (userAgent != null) {
            headers.put("User-Agent", userAgent);
        }
        impersonator.fillRequestHeaders(headers);
        return headers;
    }
}
