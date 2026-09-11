package com.github.zhkl0228.impersonator.http3.core;

import com.github.zhkl0228.impersonator.Http3Settings;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.stream.StreamInputStream;
import tech.kwik.flupke.HttpError;
import tech.kwik.flupke.HttpStream;
import tech.kwik.flupke.impl.Http3ClientConnectionImpl;
import tech.kwik.flupke.impl.HeadersFrame;
import tech.kwik.flupke.impl.Http3Frame;
import tech.kwik.qpack.impl.DecoderImpl;
import tech.kwik.qpack.impl.DynamicTable;

import java.io.*;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Flow;

/**
 * An HTTP/3 connection whose SETTINGS frame is the profile's rather than flupke's, and which honours
 * the two QPACK settings it sends.
 * <p>
 * flupke sends two settings, both zero, and offers {@code addSettingsParameter} for adding more -
 * but it refuses to let the two it manages itself be changed, and it keeps them in a
 * {@code HashMap}, so neither their values nor the order they go out in are reachable that way.
 * The map is protected, though, so a subclass can put what the profile asked for straight into it.
 * <p>
 * Those two it manages itself are exactly the QPACK ones, and they are zero for a reason: flupke
 * accepts the peer's encoder stream and never reads it, and opens no decoder stream, so it has no
 * dynamic table and says so. Chrome sends 65536 and 100. Sending those numbers means meaning them,
 * which is why this class reads the encoder stream, opens the decoder stream, and hands both to a
 * QPACK decoder that implements the dynamic table; see quic/qpack/UPSTREAM.md.
 * <p>
 * That is a liberty taken with flupke's internals and it is taken narrowly: the contents of one map
 * in the constructor, one more unidirectional stream where flupke opens its control stream, and one
 * stream handler replaced. It is also the reason flupke can stay an ordinary dependency rather than
 * becoming another vendored tree. If it ever stops working, the failure is loud - the fields and
 * methods are gone and this does not compile.
 * <p>
 * A profile may only ask for settings the implementation underneath honours; see
 * {@code Impersonator.getHttp3Settings()}.
 */
public class Http3Connection extends Http3ClientConnectionImpl implements AutoCloseable {

    private final ExecutorService executorService;
    private final DecoderImpl qpack;
    private final FieldSectionOrder ordering;
    private final QuicClientConnection quicClientConnection;
    private final Map<String, String> profileHeaders;

    /**
     * @param profileHeaders the headers the browser adds to every request, in the order it adds them;
     *                       empty for no profile. See {@link #send(HttpRequest, HttpResponse.BodyHandler)}.
     */
    Http3Connection(QuicClientConnection quicConnection, ExecutorService executorService, Map<Long, Long> settings,
                    java.util.List<String> fieldOrder, Map<String, String> profileHeaders) {
        super(quicConnection, executorService);
        this.executorService = executorService;
        this.quicClientConnection = quicConnection;
        this.profileHeaders = profileHeaders;
        if (settings != null) {
            settingsParameters.clear();
            settingsParameters.putAll(settings);
        }
        FieldSectionOrder ordering = null;
        if (fieldOrder != null) {
            // Wrapping rather than replacing: flupke's encoder still does the encoding, it just gets
            // the field lines in the browser's order. See FieldSectionOrder for why this is the only
            // point at which that order still exists.
            qpackEncoder = ordering = new FieldSectionOrder(qpackEncoder, fieldOrder);
        }
        this.ordering = ordering;
        qpack = (DecoderImpl) qpackDecoder;
        qpack.setMaxTableCapacity(advertised(Http3Settings.QPACK_MAX_TABLE_CAPACITY));
        qpack.setMaxBlockedStreams((int) advertised(Http3Settings.QPACK_BLOCKED_STREAMS));
    }

    /**
     * The request with the browser's own headers added - its User-Agent above all, but also the
     * client hints, the Accept set and the rest of what it always sends.
     * <p>
     * Here rather than in whatever put the request together, because it belongs to the connection:
     * a connection that carries a browser's QUIC, TLS and HTTP/3 fingerprint byte for byte and then a
     * request with no User-Agent at all is a plainer tell than any mismatch, and nothing above this
     * has to remember that. A header the caller set itself is left alone - the profile describes the
     * browser, not the request.
     * <p>
     * The order they end up in is not the browser's, and does not need to be: {@link HttpRequest}
     * keeps its headers in a sorted map, so they go out alphabetically whatever order they are added
     * in, and the field section is put back into the browser's order further down, where it still
     * exists. See {@link FieldSectionOrder}.
     */
    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler)
            throws IOException {
        return super.send(withProfileHeaders(request), decoding(responseBodyHandler));
    }

    @Override
    public <T> void sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler,
                              java.util.concurrent.CompletableFuture<HttpResponse<T>> result) {
        super.sendAsync(withProfileHeaders(request), decoding(responseBodyHandler), result);
    }

    /**
     * The caller's body handler, with any Content-Encoding undone first.
     * <p>
     * It belongs to the connection because the Accept-Encoding does: {@link #withProfileHeaders} adds
     * the browser's own, which asks for gzip, deflate, br and zstd, so the answer has to be decoded
     * rather than handed on compressed. That is true of every caller of this class, not only of the
     * ones that reach it through {@code java.net.http.HttpClient} - and while this lived up there, a
     * caller using {@link Http3ConnectionFactory} directly got a response body of binary noise with
     * nothing to say why.
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
                delegate.onNext(java.util.List.of(ByteBuffer.wrap(decoded)));
                delegate.onComplete();
                return delegate.getBody().toCompletableFuture().join();
            });
        };
    }

    private HttpRequest withProfileHeaders(HttpRequest request) {
        if (profileHeaders.isEmpty()) {
            return request;
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(request.uri());
        request.timeout().ifPresent(builder::timeout);
        request.version().ifPresent(builder::version);
        // Every property HttpRequest has, because this is a copy and a copy that quietly drops one is
        // worse than no copy: expectContinue defaults to false, so leaving it out turns a request that
        // asked for 100-continue into one that does not and sends its body straight away.
        builder.expectContinue(request.expectContinue());
        builder.method(request.method(), request.bodyPublisher().orElseGet(HttpRequest.BodyPublishers::noBody));
        request.headers().map().forEach((name, values) -> values.forEach(value -> builder.header(name, value)));
        for (Map.Entry<String, String> header : profileHeaders.entrySet()) {
            if (request.headers().firstValue(header.getKey()).isEmpty()) {
                builder.header(header.getKey(), header.getValue());
            }
        }
        return builder.build();
    }

    /** The QUIC connection underneath, which carries the profile's QUIC and TLS fingerprint. */
    public QuicClientConnection getQuicConnection() {
        return quicClientConnection;
    }

    /**
     * Closes the QUIC connection underneath.
     * <p>
     * The session tickets and address validation tokens this connection was given are not collected
     * here. They used to be, which made the stores depend on this method being called at all, and on
     * nothing else needing them while the connection was still alive. They now go to their stores as
     * they arrive; see Http3ConnectionFactory.newConnection.
     */
    @Override
    public void close() {
        try {
            quicClientConnection.close();
        }
        catch (RuntimeException ignored) {
            // Closing a connection that is already gone must not mask what the caller was doing.
        }
    }

    /** The field names of the last request written, in wire order; null when no order was declared. */
    public java.util.List<String> lastFieldSection() {
        return ordering == null ? null : ordering.lastFieldSection();
    }

    /** QPACK's dynamic table, for a test that wants to see whether the peer's encoder used it. */
    public DynamicTable dynamicTable() {
        return qpack.getDynamicTable();
    }

    /** How many field lines arrived as a reference into that table; see {@link #dynamicTable()}. */
    public long dynamicTableReferences() {
        return qpack.getDynamicTableReferences();
    }

    /** The blocked stream limit the decoder was given, to check it against the one advertised. */
    public int qpackMaxBlockedStreams() {
        return qpack.getMaxBlockedStreams();
    }

    /** The value this connection's SETTINGS frame carries for a setting, or zero if it carries none. */
    public long advertised(long identifier) {
        Long value = settingsParameters.get(identifier);
        return value == null ? 0 : value;
    }

    /**
     * Opens this connection's HTTP/3 streams, the QUIC connection having been brought up - or at least
     * started - by {@link Http3ConnectionFactory}.
     * <p>
     * flupke's own connect() calls {@code quicConnection.connect()} when the connection does not
     * report itself connected, which a connection in its 0-RTT window does not: it has sent its
     * ClientHello and is waiting. Calling connect() on it then is an error, and waiting for it would
     * close the window this connection exists to write in - the SETTINGS below go out as 0-RTT data
     * for the same reason a request does.
     */
    @Override
    public void connect() throws IOException {
        synchronized (this) {
            if (!streamsStarted) {
                try {
                    startControlStream();
                }
                catch (UncheckedIOException wrapped) {
                    /*
                     * flupke's startControlStream() declares no IOException, so the QPACK decoder
                     * stream this adds to it can only report one by wrapping; here is the first place
                     * that may unwrap it, connect() being declared to throw IOException by flupke's
                     * own interface. Left wrapped it goes straight past a caller that catches
                     * IOException around newConnection - which is every caller, since that is what
                     * the method declares - and out of the thread instead.
                     *
                     * Not hypothetical: anything that ends the QUIC connection in the gap between the
                     * handshake finishing and these streams being opened produces exactly this, and a
                     * soak of google.com met it four times in four hundred connections.
                     */
                    throw wrapped.getCause();
                }
                streamsStarted = true;
            }
        }
    }

    private boolean streamsStarted;

    /**
     * Reads the peer's encoder stream, which flupke stores and never looks at. Registered in place of
     * flupke's handler, which is called from the superclass constructor - so this refers to nothing
     * of this class that is not there yet.
     */
    @Override
    protected void registerStandardStreamHandlers() {
        super.registerStandardStreamHandlers();
        unidirectionalStreamHandler.put((long) STREAM_TYPE_QPACK_ENCODER, this::readEncoderStream);
    }

    private void readEncoderStream(HttpStream httpStream) {
        executorService.execute(() -> {
            try {
                qpack.decodeEncoderStream(httpStream.getInputStream());
                // RFC 9204 section 4.2: "The sender MUST NOT close [the encoder] stream", so reaching
                // the end of it means the connection is over, one way or another.
                qpack.getDynamicTable().encoderStreamFailed(
                        new EOFException("the peer closed its QPACK encoder stream"));
            }
            catch (Throwable failure) {
                // Anything blocked on an insert that is now never coming has to hear about it here;
                // this thread is the only one that would ever have delivered it.
                qpack.getDynamicTable().encoderStreamFailed(failure);
            }
        });
    }

    /**
     * Opens the QPACK decoder stream alongside flupke's control stream, which is where a connection's
     * unidirectional streams are opened.
     * <p>
     * It cannot go through {@code createUnidirectionalStream}, which refuses the four stream types
     * RFC 9114 defines, so it is opened the way {@code startControlStream} opens its own.
     * <p>
     * Both of them are 0-RTT data on a connection that is resuming, and neither has to know it: they
     * are opened while the connection is in its 0-RTT window, where every stream writes at that
     * level. flupke's own startControlStream, called below, writes the SETTINGS frame in the first
     * flight without a line of it being about early data.
     */
    @Override
    protected void startControlStream() {
        super.startControlStream();
        try {
            QuicStream decoderStream = quicConnection.createStream(false);
            OutputStream output = decoderStream.getOutputStream();
            output.write(STREAM_TYPE_QPACK_DECODER);
            output.flush();
            qpack.setDecoderStream(output);
        }
        catch (IOException e) {
            // Without it the peer never learns what arrived, so a field section that refers to the
            // dynamic table can never be acknowledged; that is not something to carry on from.
            throw new UncheckedIOException("could not open the QPACK decoder stream", e);
        }
    }

    /**
     * Decodes a field section with <em>this connection's</em> QPACK decoder, for a caller reading
     * HEADERS off a stream it manages itself.
     * <p>
     * A throwaway {@code Decoder.newBuilder().build()} is enough only against a peer that was told
     * there is no dynamic table. This connection tells it the opposite - it sends the browser's
     * SETTINGS, which invite the peer's encoder to keep a 65536 byte table and to reference entries
     * it has not finished delivering - so a field section it sends may name an entry that exists only
     * in the decoder that has been reading the encoder stream. That decoder is this one; a fresh one
     * cannot decode such a section and never will, because the inserts went past it.
     * <p>
     * It is also the only decoder that can acknowledge the section. RFC 9204 section 4.4.1: "After
     * the decoder finishes decoding a field section encoded using representations containing dynamic
     * table references, it MUST emit a Section Acknowledgment instruction" - on the decoder stream,
     * naming the stream the section arrived on. Hence the stream id: without it the acknowledgment
     * cannot be written, the peer's Known Received Count never moves, and its encoder is left holding
     * entries it believes may not have arrived.
     *
     * @param streamId the stream the section was read from
     * @param headerBlock the field section's bytes, without the HEADERS frame header
     * @throws tech.kwik.qpack.impl.HttpQPackDecompressionFailedException if it cannot be decoded,
     *             which for a section that needs an entry this connection has not been sent is what
     *             happens rather than a header field nobody wrote
     */
    public HeadersFrame parseHeaders(long streamId, byte[] headerBlock) throws IOException {
        qpack.setSectionStreamId(streamId);
        return new HeadersFrame().parsePayload(headerBlock, qpack);
    }

    /**
     * Tells the decoder which stream the frame about to be read came in on, so that a field section
     * can be acknowledged by stream id as RFC 9204 section 4.4.1 requires. This is the last point
     * where both are in hand: flupke's {@code readHeadersFrame} is private and passes the decoder the
     * section's bytes and nothing else.
     */
    @Override
    protected Http3Frame readFrame(InputStream input, long maxHeadersSize, long maxDataSize) throws IOException, HttpError {
        /*
         * And waits for the handshake, which is where a connection started in its 0-RTT window
         * finishes being made. Here rather than anywhere earlier because this is the first moment
         * anything is expected back: flupke writes the whole request and then reads it, so the request
         * has gone out - in 0-RTT packets, the window still being open - by the time this is reached.
         *
         * It is also what has to happen before the answer can be read at all when the server refuses
         * the early data: awaitConnected sends the refused request again, and reading the response
         * before that would be reading for an answer to something the server threw away.
         */
        ((QuicClientConnection) quicConnection).awaitConnected();
        qpack.setSectionStreamId(input instanceof StreamInputStream
                ? ((StreamInputStream) input).getStreamId()
                : null);
        return super.readFrame(input, maxHeadersSize, maxDataSize);
    }
}
