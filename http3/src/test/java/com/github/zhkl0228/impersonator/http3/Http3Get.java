package com.github.zhkl0228.impersonator.http3;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * One GET over HTTP/3 with a client the given factory built, closed straight away.
 * <p>
 * A fresh client per call on purpose: every test here is about the handshake, so reusing a pooled
 * connection would test nothing.
 */
class Http3Get {

    static String body(Http3ClientFactory factory, String url) throws Exception {
        try (HttpClient client = factory.newHttpClient()) {
            HttpResponse<String> response = client.send(HttpRequest.newBuilder(URI.create(url)).build(),
                    HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                throw new IOException("GET " + url + " returned " + response.statusCode());
            }
            return response.body();
        }
    }
}
