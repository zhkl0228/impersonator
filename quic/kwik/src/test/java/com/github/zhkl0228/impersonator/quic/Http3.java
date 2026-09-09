package com.github.zhkl0228.impersonator.quic;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.flupke.Http3SingleConnectionClient;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * One HTTP/3 request over one QUIC connection built by a {@link QuicClientFactory}.
 * <p>
 * Deliberately not flupke's {@code Http3Client}: that builds the QUIC connection itself, so there is
 * nowhere to put the profile. Going through {@code Http3SingleConnectionClient}, which takes a
 * connection that is already made, is what proves the profile really travels with the connection
 * rather than sitting in a static somewhere. The {@code http3} module will make this ergonomic; here
 * it is deliberately explicit.
 */
class Http3 {

    private static final Duration TIMEOUT = Duration.ofSeconds(15);

    static HttpResponse<String> get(QuicClientFactory factory, String url) throws Exception {
        QuicClientConnection connection = factory.newBuilder()
                .uri(URI.create(url))
                .port(443)
                .applicationProtocol("h3")
                .connectTimeout(TIMEOUT)
                .build();
        try {
            connection.connect();
            HttpClient client = new Http3SingleConnectionClient(connection, TIMEOUT, null);
            return client.send(HttpRequest.newBuilder(URI.create(url)).build(), HttpResponse.BodyHandlers.ofString());
        } finally {
            try {
                connection.close();
            } catch (RuntimeException ignored) {
                // The connection may already be gone; a close failure must not hide the real result.
            }
        }
    }

    static String body(QuicClientFactory factory, String url) throws Exception {
        HttpResponse<String> response = get(factory, url);
        if (response.statusCode() != 200) {
            throw new IOException("GET " + url + " returned " + response.statusCode());
        }
        return response.body();
    }
}
