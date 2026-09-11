package com.github.zhkl0228.impersonator.http3;

import tech.kwik.core.QuicClientConnection;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.TimeUnit;

/**
 * One GET over HTTP/3 with a client the given factory built, closed once the session ticket is in.
 * <p>
 * A fresh client per call on purpose: every test here is about the handshake, so reusing a pooled
 * connection would test nothing.
 */
class Http3Get {

    /**
     * How long the connection is left open after the response, waiting for the session ticket.
     * <p>
     * A server's NewSessionTicket comes after the handshake and is not tied to the response, so it
     * can arrive after it. Closing the moment the body is in therefore loses the ticket now and then,
     * and the next connection full-handshakes - which fails a resumption test for a reason that has
     * nothing to do with what it is testing. Measured over fifteen connections to the fingerprint
     * endpoint, the ticket was already in when the response landed fourteen times and came 475 ms
     * later once, so this waits for the ticket itself rather than for a length of time: the usual
     * connection pays nothing and the slow one is not lost.
     * <p>
     * A test-side fix on purpose. No browser closes a connection the instant a response lands, so the
     * race is this helper's and not the client's, and buying the ticket with a wait inside
     * {@code Http3Client.close()} would slow every real close for it.
     */
    private static final long MAX_SETTLE_MILLIS = 2000;

    /** The status of one GET, for a test that is about reaching the host rather than what it said. */
    static int status(Http3ClientFactory factory, String url) throws Exception {
        try (HttpClient client = factory.newHttpClient()) {
            int status = client.send(HttpRequest.newBuilder(URI.create(url)).build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode();
            settle(client, url);
            return status;
        }
    }

    static String body(Http3ClientFactory factory, String url) throws Exception {
        try (HttpClient client = factory.newHttpClient()) {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(url)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("GET " + url + " returned " + response.statusCode());
            }
            settle(client, url);
            return response.body();
        }
    }

    /** The authority a client keeps its connection to that URL under. */
    static String authorityOf(String url) {
        URI uri = URI.create(url);
        return uri.getHost() + ":" + (uri.getPort() == -1 ? 443 : uri.getPort());
    }

    private static void settle(HttpClient client, String url) throws InterruptedException {
        QuicClientConnection connection = ((Http3Client) client).quicConnectionFor(authorityOf(url));
        if (connection == null) {
            return;
        }
        long deadline = System.currentTimeMillis() + MAX_SETTLE_MILLIS;
        while (connection.getNewSessionTickets().isEmpty() && System.currentTimeMillis() < deadline) {
            TimeUnit.MILLISECONDS.sleep(10);
        }
    }
}
