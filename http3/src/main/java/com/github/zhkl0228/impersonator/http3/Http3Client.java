package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.http3.core.Http3Connection;
import com.github.zhkl0228.impersonator.http3.core.Http3ConnectionFactory;
import tech.kwik.core.QuicClientConnection;

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
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
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

    private final Http3ConnectionFactory connectionFactory;
    private final Map<String, Http3Connection> connections = new ConcurrentHashMap<>();

    private volatile boolean closed;

    Http3Client(Http3ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    // The connection is this client's for as long as the client lives, so it is not closed here; see
    // connectionFor. Same below.
    @SuppressWarnings("resource")
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        // The browser's own headers are the connection's doing, not this class's; see
        // Http3Connection.send. What is this class's is undoing the Content-Encoding they ask for.
        return connectionFor(request.uri()).send(request, decoding(responseBodyHandler));
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

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler) {
        return sendAsync(request, responseBodyHandler, null);
    }

    @SuppressWarnings("resource")
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
     * The connection to an authority, opened on first use.
     * <p>
     * Opened here rather than lazily inside flupke, because a handshake failure should surface as the
     * IOException of the request that caused it. Everything about what the connection is comes from
     * {@link Http3ConnectionFactory}; what this class adds is that there is one per authority and
     * that it is kept.
     * <p>
     * The connection is {@link AutoCloseable} and is deliberately not closed here: this client owns
     * it until {@link #close()}, which is the whole point of keeping one per authority. The only one
     * closed on the spot is the one that loses the race below.
     */
    private Http3Connection connectionFor(URI uri) throws IOException {
        String authority = authorityOf(uri);
        Http3Connection existing = connections.get(authority);
        if (existing != null) {
            return existing;
        }
        Http3Connection connection = connectionFactory.newConnection(uri);
        Http3Connection raced = connections.putIfAbsent(authority, connection);
        if (raced != null) {
            // Another thread got there first; keep theirs and drop the connection just opened.
            connection.close();
            return raced;
        }
        return connection;
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
        return connections.get(authority);
    }

    /**
     * The QUIC connection to an authority, or null when there is none. Package private and here for
     * the same reason as {@link #openConnection(String)}: whether a connection resumed, and whether
     * it wrote 0-RTT data, is a property of the handshake and unreachable once a request has gone
     * through it.
     */
    QuicClientConnection quicConnectionFor(String authority) {
        Http3Connection connection = connections.get(authority);
        return connection == null ? null : connection.getQuicConnection();
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
        for (String authority : connections.keySet()) {
            Http3Connection connection = connections.remove(authority);
            if (connection != null) {
                // Which is also where its session ticket and address validation token are kept for
                // the next connection to that host; see Http3Connection.close.
                connection.close();
            }
        }
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
        return Optional.of(connectionFactory.getConnectTimeout());
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
        return Optional.of(connectionFactory.getExecutor());
    }
}
