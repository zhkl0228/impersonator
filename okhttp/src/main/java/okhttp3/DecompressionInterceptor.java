package okhttp3;

import okhttp3.CompressionInterceptor.DecompressionAlgorithm;
import okio.BufferedSource;
import okio.InflaterSource;
import okio.Okio;
import okio.Source;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.zip.Inflater;

/**
 * Decompresses a response according to its {@code Content-Encoding}.
 * <p>
 * okhttp already does this for the {@code Accept-Encoding: gzip} it adds itself, but only then: a
 * request that carries its own {@code Accept-Encoding} is left alone, body included. A profile has
 * to send its own header to control both the value and its position among the other headers, both
 * of which are part of the fingerprint, so the decompression has to be done here instead.
 * <p>
 * When okhttp did handle it, it removes {@code Content-Encoding} on the way out, so this
 * interceptor sees nothing to do.
 */
public class DecompressionInterceptor implements Interceptor {

    private static final DecompressionAlgorithm DEFLATE = new DecompressionAlgorithm() {
        @NotNull
        @Override
        public String getEncoding() {
            return "deflate";
        }

        @NotNull
        @Override
        public Source decompress(@NotNull BufferedSource compressedSource) {
            return new InflaterSource(compressedSource, new Inflater());
        }
    };

    private static final DecompressionAlgorithm BROTLI = new DecompressionAlgorithm() {
        @NotNull
        @Override
        public String getEncoding() {
            return "br";
        }

        @NotNull
        @Override
        public Source decompress(@NotNull BufferedSource compressedSource) {
            try {
                return Okio.source(new org.brotli.dec.BrotliInputStream(compressedSource.inputStream()));
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
    };

    private static final DecompressionAlgorithm ZSTD = new DecompressionAlgorithm() {
        @NotNull
        @Override
        public String getEncoding() {
            return "zstd";
        }

        @NotNull
        @Override
        public Source decompress(@NotNull BufferedSource compressedSource) {
            return Okio.source(new io.airlift.compress.zstd.ZstdInputStream(compressedSource.inputStream()));
        }
    };

    public static final DecompressionInterceptor DEFAULT =
            new DecompressionInterceptor(Gzip.INSTANCE, DEFLATE, BROTLI, ZSTD);

    private final List<DecompressionAlgorithm> algorithms;

    public DecompressionInterceptor(DecompressionAlgorithm... algorithms) {
        this.algorithms = Arrays.asList(algorithms);
    }

    @NotNull
    @Override
    public Response intercept(@NotNull Chain chain) throws IOException {
        Response response = chain.proceed(chain.request());

        String encoding = response.header("Content-Encoding");
        if (encoding == null || "identity".equalsIgnoreCase(encoding)) {
            return response;
        }
        ResponseBody body = response.body();

        DecompressionAlgorithm algorithm = null;
        for (DecompressionAlgorithm candidate : algorithms) {
            if (candidate.getEncoding().equalsIgnoreCase(encoding)) {
                algorithm = candidate;
                break;
            }
        }
        if (algorithm == null) {
            /*
             * A server must only use an encoding the request advertised, so this is either a broken
             * server or an encoding this interceptor was not built with. Either way the body cannot
             * be read, and returning it compressed would surface much later as unreadable content.
             */
            throw new IOException("cannot decode Content-Encoding: " + encoding + "; "
                    + chain.request().url() + " was offered " + acceptEncoding());
        }

        BufferedSource decompressed = Okio.buffer(algorithm.decompress(body.source()));
        return response.newBuilder()
                .removeHeader("Content-Encoding")
                .removeHeader("Content-Length")
                .body(ResponseBody.create(decompressed, body.contentType(), -1L))
                .build();
    }

    /** The {@code Accept-Encoding} value matching the algorithms this instance can decode. */
    public String acceptEncoding() {
        StringBuilder sb = new StringBuilder();
        for (DecompressionAlgorithm algorithm : algorithms) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(algorithm.getEncoding().toLowerCase(Locale.US));
        }
        return sb.toString();
    }
}
