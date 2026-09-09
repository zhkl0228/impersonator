package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.quic.QuicClientFactory;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.quic.SessionTicketStore;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.flupke.Http3ClientConnection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.nio.ByteBuffer;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;

/**
 * One QUIC connection per host and port, each carrying the factory's profile, behind one
 * {@link HttpClient}.
 * <p>
 * flupke's own {@code Http3Client} builds the QUIC connection itself, so there is nowhere to put a
 * profile; its {@code Http3SingleConnectionClient} takes a connection that is already made, which is
 * the seam this uses. Keeping to that public API is what lets flupke stay an ordinary dependency
 * rather than a third vendored tree.
 */
class Http3Client extends HttpClient {

    private final QuicClientFactory quicClientFactory;
    private final Map<Long, Long> http3Settings;
    private final Duration connectTimeout;
    private final Map<String, Connection> connections = new ConcurrentHashMap<>();
    /** Daemon threads, so an unclosed client cannot keep the JVM alive. */
    private final ExecutorService executorService =
            Executors.newCachedThreadPool(new DaemonThreadFactory("impersonator-http3"));

    private volatile boolean closed;

    /** The profile whose request headers every request through this client carries; null when none. */
    private final Impersonator impersonator;

    Http3Client(QuicClientFactory quicClientFactory, Map<Long, Long> http3Settings, Duration connectTimeout,
                Impersonator impersonator) {
        this.quicClientFactory = quicClientFactory;
        this.http3Settings = http3Settings;
        this.connectTimeout = connectTimeout;
        this.impersonator = impersonator;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        HttpRequest impersonated = withProfileHeaders(request);
        return connectionFor(impersonated.uri()).send(impersonated, decoding(responseBodyHandler));
    }

    /**
     * The caller's body handler, with any Content-Encoding undone first.
     * <p>
     * The profile's Accept-Encoding asks for gzip, deflate, br and zstd because that is what the
     * browser asks for, so the answer has to be decoded rather than handed on compressed - which is
     * what happened for one run of the tests, and looked like a response body of binary noise.
     * <p>
     * The body is buffered whole to decode it, which is what decoding needs anyway, and then fed to
     * the handler the caller gave. A response with no Content-Encoding goes straight through and is
     * not buffered.
     */
    private <T> HttpResponse.BodyHandler<T> decoding(HttpResponse.BodyHandler<T> handler) {
        return responseInfo -> {
            String contentEncoding = responseInfo.headers().firstValue("content-encoding").orElse(null);
            if (!ContentEncoding.isEncoded(contentEncoding)) {
                return handler.apply(responseInfo);
            }
            return HttpResponse.BodySubscribers.mapping(HttpResponse.BodySubscribers.ofByteArray(), body -> {
                byte[] decoded;
                try {
                    decoded = ContentEncoding.decode(contentEncoding, body);
                }
                catch (IOException e) {
                    throw new UncheckedIOException("decode a " + contentEncoding + " response body", e);
                }
                HttpResponse.BodySubscriber<T> delegate = handler.apply(responseInfo);
                delegate.onSubscribe(new Flow.Subscription() {
                    @Override
                    public void request(long n) {
                    }

                    @Override
                    public void cancel() {
                    }
                });
                delegate.onNext(List.of(ByteBuffer.wrap(decoded)));
                delegate.onComplete();
                return delegate.getBody().toCompletableFuture().join();
            });
        };
    }

    /**
     * The request with the browser's own headers added - its User-Agent above all, but also the
     * client hints, the Accept set and the rest of what it always sends.
     * <p>
     * Without this a connection whose QUIC, TLS and HTTP/3 fingerprints match a browser byte for byte
     * carries a request with no User-Agent at all, which is a plainer tell than any mismatch. A header
     * the caller set itself is left alone: the profile describes the browser, not the request.
     * <p>
     * The order they end up in is not the browser's. {@link HttpRequest} keeps its headers in a sorted
     * map, so they go out alphabetically whatever order they are added in, and matching a browser's
     * order means building the field section without java.net.http's help.
     */
    private HttpRequest withProfileHeaders(HttpRequest request) {
        if (impersonator == null) {
            return request;
        }
        Map<String, String> headers = new LinkedHashMap<>();
        // Seeded first, because a profile moves the User-Agent rather than supplying it.
        String userAgent = impersonator.getUserAgent();
        if (userAgent != null) {
            headers.put("User-Agent", userAgent);
        }
        impersonator.fillRequestHeaders(headers);
        if (headers.isEmpty()) {
            return request;
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri());
        request.timeout().ifPresent(builder::timeout);
        request.version().ifPresent(builder::version);
        builder.method(request.method(), request.bodyPublisher().orElseGet(HttpRequest.BodyPublishers::noBody));
        request.headers().map().forEach((name, values) -> values.forEach(value -> builder.header(name, value)));
        for (Map.Entry<String, String> header : headers.entrySet()) {
            if (request.headers().firstValue(header.getKey()).isEmpty()) {
                builder.header(header.getKey(), header.getValue());
            }
        }
        return builder.build();
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler) {
        return sendAsync(request, responseBodyHandler, null);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler,
                                                            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        CompletableFuture<HttpResponse<T>> result = new CompletableFuture<>();
        try {
            // HTTP/3 has no push promise in RFC 9114 the way HTTP/2 did, and flupke offers no hook for
            // one, so a handler is accepted and never called rather than silently dropped elsewhere.
            connectionFor(request.uri()).sendAsync(request, responseBodyHandler, result);
        } catch (IOException e) {
            result.completeExceptionally(e);
        }
        return result;
    }

    /**
     * The connection is opened here rather than lazily inside flupke, because
     * {@code Http3SingleConnectionClient} expects one that is already connected, and because a
     * handshake failure should surface as the IOException of the request that caused it.
     */
    private Http3ClientConnection connectionFor(URI uri) throws IOException {
        String authority = authorityOf(uri);
        Connection existing = connections.get(authority);
        if (existing != null) {
            return existing.http3Connection;
        }

        /*
         * A ticket kept from an earlier connection to this host turns the handshake into a resumed
         * one: the ClientHello carries "pre_shared_key" and "early_data" and is a different message
         * with a different JA4, which is what a browser's second visit to a host looks like. Without
         * this every connection is a full handshake for ever, which no browser's history contains.
         */
        SessionTicketStore sessionTicketStore = quicClientFactory.getSessionTicketStore();
        QuicSessionTicket ticket = sessionTicketStore == null ? null : sessionTicketStore.take(uri.getHost());

        QuicClientConnection quicConnection = quicClientFactory.newBuilder()
                .uri(uri)
                .port(portOf(uri))
                .applicationProtocol("h3")
                .connectTimeout(connectTimeout)
                .sessionTicket(ticket)
                .build();

        // Constructed before the QUIC connection is up, because the constructor is what registers
        // the callback for peer-initiated streams and kwik drops any that arrive before there is
        // one - silently, its default being a no-op consumer. The server opens its control and QPACK
        // encoder streams as soon as the handshake completes, so connecting first loses whichever of
        // them wins the race, and the QPACK one carries the dynamic table. Http3Connection.connect()
        // brings the QUIC connection up itself.
        Http3Connection http3Connection = new Http3Connection(quicConnection, executorService, http3Settings);
        if (ticket != null) {
            /*
             * Resuming, so this connection sends 0-RTT data, and what HTTP/3 has to send first is its
             * control stream and SETTINGS. The QUIC connection is brought up here rather than by
             * http3Connection.connect() because the early data has to be written between the
             * ClientHello and the end of the handshake, which is a window only this call has.
             * Offering "early_data" and sending nothing would be a claim about this client that is
             * not true - the same mistake as advertising a QPACK dynamic table there is no decoder
             * for, which is why kwik insists a writer writes something.
             */
            quicConnection.connect(sender -> http3Connection.sendControlStreamAsEarlyData(sender));
        }
        http3Connection.connect();

        Connection connection = new Connection(uri.getHost(), quicConnection, http3Connection);
        Connection raced = connections.putIfAbsent(authority, connection);
        if (raced != null) {
            // Another thread got there first; keep theirs and drop the connection just opened.
            connection.close(sessionTicketStore);
            return raced.http3Connection;
        }
        return connection.http3Connection;
    }

    /**
     * The QUIC connection is kept alongside the HTTP/3 one because closing is the caller's business
     * and the HTTP/3 connection does not own the QUIC one it was handed.
     */
    private static class Connection {
        final String host;
        final QuicClientConnection quicConnection;
        final Http3ClientConnection http3Connection;

        Connection(String host, QuicClientConnection quicConnection, Http3ClientConnection http3Connection) {
            this.host = host;
            this.quicConnection = quicConnection;
            this.http3Connection = http3Connection;
        }

        void close(SessionTicketStore sessionTicketStore) {
            /*
             * The tickets are collected here rather than after the handshake because that is not when
             * they arrive: a server sends its NewSessionTickets once the handshake is over, so asking
             * a connection for them at the moment it is done with is the first point they are all in.
             */
            if (sessionTicketStore != null) {
                try {
                    sessionTicketStore.put(host, quicConnection.getNewSessionTickets());
                } catch (RuntimeException ignored) {
                    // A ticket that cannot be kept costs the next connection a full handshake, nothing more.
                }
            }
            try {
                quicConnection.close();
            } catch (RuntimeException ignored) {
                // Closing a connection that is already gone must not mask what the caller was doing.
            }
        }
    }

    /**
     * The connection open to an authority ({@code host:port}), or null when there is none.
     * <p>
     * Package private and here for the tests. Whether the peer's QPACK encoder really used the
     * dynamic table is a property of the connection, and a connection is otherwise unreachable once
     * a request has gone through it - so without this, "we advertise a dynamic table" could only be
     * tested by observing that nothing broke, which is not the same claim.
     */
    Http3Connection openConnection(String authority) {
        Connection connection = connections.get(authority);
        return connection == null ? null : (Http3Connection) connection.http3Connection;
    }

    /**
     * The QUIC connection to an authority, or null when there is none. Package private and here for
     * the same reason as {@link #openConnection(String)}: whether a connection resumed, and whether
     * it wrote 0-RTT data, is a property of the handshake and unreachable once a request has gone
     * through it.
     */
    QuicClientConnection quicConnectionFor(String authority) {
        Connection connection = connections.get(authority);
        return connection == null ? null : connection.quicConnection;
    }

    private static String authorityOf(URI uri) {
        Objects.requireNonNull(uri.getHost(), () -> "no host in " + uri);
        return uri.getHost() + ":" + portOf(uri);
    }

    private static int portOf(URI uri) {
        return uri.getPort() == -1 ? 443 : uri.getPort();
    }

    /**
     * Closes every QUIC connection this client opened.
     * <p>
     * {@link #shutdown()} does the same thing, and says so rather than pretending: this client keeps
     * no register of requests in flight, so there is nothing to let finish first. A request running
     * on another thread while this is called will fail, which is what closing its connection means.
     */
    @Override
    public void close() {
        closed = true;
        SessionTicketStore sessionTicketStore = quicClientFactory.getSessionTicketStore();
        for (String authority : connections.keySet()) {
            Connection connection = connections.remove(authority);
            if (connection != null) {
                connection.close(sessionTicketStore);
            }
        }
        // After the connections, because collecting their session tickets is the last thing they are
        // asked for and closing this first would take the threads that answer.
        executorService.shutdownNow();
    }

    /** No orderly variant exists here; see {@link #close()}. */
    @Override
    public void shutdown() {
        close();
    }

    /** No orderly variant exists here; see {@link #close()}. */
    @Override
    public void shutdownNow() {
        close();
    }

    @Override
    public boolean isTerminated() {
        return closed && connections.isEmpty();
    }

    /** Closing is synchronous, so there is never anything to await. */
    @Override
    public boolean awaitTermination(Duration duration) {
        return isTerminated();
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return Optional.empty();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return Optional.of(connectTimeout);
    }

    @Override
    public Redirect followRedirects() {
        // As flupke: HTTP/3 responses are handed back as they arrive, redirects included.
        return Redirect.NEVER;
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return Optional.empty();
    }

    @Override
    public SSLContext sslContext() {
        // QUIC carries its own TLS 1.3; there is no SSLContext behind this client.
        return null;
    }

    @Override
    public SSLParameters sslParameters() {
        return null;
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return Optional.empty();
    }

    @Override
    public Version version() {
        // java.net.http.HttpClient.Version has no HTTP_3, and naming HTTP_2 here would be a lie.
        return null;
    }

    @Override
    public Optional<Executor> executor() {
        return Optional.of(executorService);
    }
}
