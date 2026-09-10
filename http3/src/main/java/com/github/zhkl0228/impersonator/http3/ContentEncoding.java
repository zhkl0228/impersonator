package com.github.zhkl0228.impersonator.http3;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * Undoing the Content-Encoding of a response.
 * <p>
 * A browser profile's request headers include the Accept-Encoding the browser sends, and Chrome's is
 * {@code gzip, deflate, br, zstd}. Asking for those and then handing the caller the compressed bytes
 * is the same mistake as advertising a QPACK dynamic table with no decoder behind it - the difference
 * being that this one is not subtle, it is a response body of binary noise. So everything the header
 * asks for is decoded here, and the header stays what the browser sends rather than being trimmed to
 * what is convenient.
 * <p>
 * The decoders are the ones the TLS certificate compression of RFC 8879 already brought in, so this
 * costs no new dependency.
 */
final class ContentEncoding {

    private ContentEncoding() {
    }

    /** Whether a response with this Content-Encoding needs decoding at all. */
    static boolean isEncoded(String contentEncoding) {
        return contentEncoding != null
                && !contentEncoding.isEmpty()
                && !"identity".equalsIgnoreCase(contentEncoding.trim());
    }

    /**
     * @param contentEncoding the header's value, which may name several encodings applied in order
     * @throws IOException if the body does not decode, which is a broken response and not something
     *                     to hand on as if it were the content
     */
    static byte[] decode(String contentEncoding, byte[] body) throws IOException {
        byte[] decoded = body;
        String[] encodings = contentEncoding.split(",");
        // Applied in the order they were applied, so undone from the last backwards.
        for (int i = encodings.length - 1; i >= 0; i--) {
            decoded = decodeOne(encodings[i].trim(), decoded);
        }
        return decoded;
    }

    private static byte[] decodeOne(String encoding, byte[] body) throws IOException {
        if (encoding.isEmpty() || "identity".equalsIgnoreCase(encoding)) {
            return body;
        }
        try (InputStream in = open(encoding, body)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(body.length * 4);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static InputStream open(String encoding, byte[] body) throws IOException {
        ByteArrayInputStream compressed = new ByteArrayInputStream(body);
        if ("gzip".equalsIgnoreCase(encoding) || "x-gzip".equalsIgnoreCase(encoding)) {
            return new GZIPInputStream(compressed);
        }
        if ("deflate".equalsIgnoreCase(encoding)) {
            return new InflaterInputStream(compressed);
        }
        if ("br".equalsIgnoreCase(encoding)) {
            return new org.brotli.dec.BrotliInputStream(compressed);
        }
        if ("zstd".equalsIgnoreCase(encoding)) {
            return new io.airlift.compress.zstd.ZstdInputStream(compressed);
        }
        // Only the encodings the profiles ask for are decoded; one that was never requested arriving
        // anyway is the server's error, and passing the bytes on as content would hide it.
        throw new IOException("unsupported Content-Encoding \"" + encoding + "\"; this client asks for"
                + " gzip, deflate, br and zstd");
    }
}
