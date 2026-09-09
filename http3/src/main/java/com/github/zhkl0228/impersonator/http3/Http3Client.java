package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.quic.QuicClientFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.concurrent.DaemonThreadFactory;
import tech.kwik.flupke.Http3ClientConnection;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    Http3Client(QuicClientFactory quicClientFactory, Map<Long, Long> http3Settings, Duration connectTimeout) {
        this.quicClientFactory = quicClientFactory;
        this.http3Settings = http3Settings;
        this.connectTimeout = connectTimeout;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        return connectionFor(request.uri()).send(request, responseBodyHandler);
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

        QuicClientConnection quicConnection = quicClientFactory.newBuilder()
                .uri(uri)
                .port(portOf(uri))
                .applicationProtocol("h3")
                .connectTimeout(connectTimeout)
                .build();
        quicConnection.connect();

        Http3Connection http3Connection = new Http3Connection(quicConnection, executorService, http3Settings);
        http3Connection.connect();

        Connection connection = new Connection(quicConnection, http3Connection);
        Connection raced = connections.putIfAbsent(authority, connection);
        if (raced != null) {
            // Another thread got there first; keep theirs and drop the connection just opened.
            connection.close();
            return raced.http3Connection;
        }
        return connection.http3Connection;
    }

    /**
     * The QUIC connection is kept alongside the HTTP/3 one because closing is the caller's business
     * and the HTTP/3 connection does not own the QUIC one it was handed.
     */
    private static class Connection {
        final QuicClientConnection quicConnection;
        final Http3ClientConnection http3Connection;

        Connection(QuicClientConnection quicConnection, Http3ClientConnection http3Connection) {
            this.quicConnection = quicConnection;
            this.http3Connection = http3Connection;
        }

        void close() {
            try {
                quicConnection.close();
            } catch (RuntimeException ignored) {
                // Closing a connection that is already gone must not mask what the caller was doing.
            }
        }
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
        executorService.shutdownNow();
        for (String authority : connections.keySet()) {
            Connection connection = connections.remove(authority);
            if (connection != null) {
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
