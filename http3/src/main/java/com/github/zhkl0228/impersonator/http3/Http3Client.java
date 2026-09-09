package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.http3.Http3ClientFactory.CloseableHttpClient;
import com.github.zhkl0228.impersonator.quic.QuicClientFactory;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.flupke.Http3SingleConnectionClient;

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

/**
 * One QUIC connection per host and port, each carrying the factory's profile, behind one
 * {@link HttpClient}.
 * <p>
 * flupke's own {@code Http3Client} builds the QUIC connection itself, so there is nowhere to put a
 * profile; its {@code Http3SingleConnectionClient} takes a connection that is already made, which is
 * the seam this uses. Keeping to that public API is what lets flupke stay an ordinary dependency
 * rather than a third vendored tree.
 */
class Http3Client extends CloseableHttpClient {

    private final QuicClientFactory quicClientFactory;
    private final Duration connectTimeout;
    private final Map<String, Connection> connections = new ConcurrentHashMap<>();

    Http3Client(QuicClientFactory quicClientFactory, Duration connectTimeout) {
        this.quicClientFactory = quicClientFactory;
        this.connectTimeout = connectTimeout;
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException, InterruptedException {
        return clientFor(request.uri()).send(request, responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler) {
        try {
            return clientFor(request.uri()).sendAsync(request, responseBodyHandler);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,
                                                            HttpResponse.BodyHandler<T> responseBodyHandler,
                                                            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        try {
            return clientFor(request.uri()).sendAsync(request, responseBodyHandler, pushPromiseHandler);
        } catch (IOException e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * The connection is opened here rather than lazily inside flupke, because
     * {@code Http3SingleConnectionClient} expects one that is already connected, and because a
     * handshake failure should surface as the IOException of the request that caused it.
     */
    private HttpClient clientFor(URI uri) throws IOException {
        String authority = authorityOf(uri);
        Connection existing = connections.get(authority);
        if (existing != null) {
            return existing.client;
        }

        QuicClientConnection quicConnection = quicClientFactory.newBuilder()
                .uri(uri)
                .port(portOf(uri))
                .applicationProtocol("h3")
                .connectTimeout(connectTimeout)
                .build();
        quicConnection.connect();

        Connection connection = new Connection(quicConnection,
                new Http3SingleConnectionClient(quicConnection, connectTimeout, null));
        Connection raced = connections.putIfAbsent(authority, connection);
        if (raced != null) {
            // Another thread got there first; keep theirs and drop the connection just opened.
            connection.close();
            return raced.client;
        }
        return connection.client;
    }

    /**
     * The QUIC connection is kept alongside the client because closing is the caller's business and
     * {@code Http3SingleConnectionClient} offers no way to do it - it takes a connection it does not
     * own.
     */
    private static class Connection {
        final QuicClientConnection quicConnection;
        final HttpClient client;

        Connection(QuicClientConnection quicConnection, HttpClient client) {
            this.quicConnection = quicConnection;
            this.client = client;
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
     * Closes every connection this client opened. A later request opens a new one, so this is a
     * reset as much as a shutdown.
     */
    @Override
    public void close() {
        for (String authority : connections.keySet()) {
            Connection connection = connections.remove(authority);
            if (connection != null) {
                connection.close();
            }
        }
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
        return Optional.empty();
    }
}
