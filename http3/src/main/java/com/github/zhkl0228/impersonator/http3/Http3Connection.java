package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.Http3Settings;

import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.stream.StreamInputStream;
import tech.kwik.flupke.HttpStream;
import tech.kwik.flupke.HttpError;
import tech.kwik.flupke.impl.Http3ClientConnectionImpl;
import tech.kwik.flupke.impl.Http3Frame;
import tech.kwik.flupke.impl.SettingsFrame;
import tech.kwik.qpack.impl.DecoderImpl;
import tech.kwik.qpack.impl.DynamicTable;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.io.UncheckedIOException;
import java.util.Map;
import java.util.concurrent.ExecutorService;

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
class Http3Connection extends Http3ClientConnectionImpl {

    private final ExecutorService executorService;
    private final DecoderImpl qpack;
    private final FieldSectionOrder ordering;

    /** Set when the control stream has already gone out in 0-RTT, so flupke must not open a second. */
    private volatile boolean controlStreamSentAsEarlyData;

    Http3Connection(QuicConnection quicConnection, ExecutorService executorService, Map<Long, Long> settings,
                    java.util.List<String> fieldOrder) {
        super(quicConnection, executorService);
        this.executorService = executorService;
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

    /** The field names of the last request written, in wire order; null when no order was declared. */
    java.util.List<String> lastFieldSection() {
        return ordering == null ? null : ordering.lastFieldSection();
    }

    /** QPACK's dynamic table, for a test that wants to see whether the peer's encoder used it. */
    DynamicTable dynamicTable() {
        return qpack.getDynamicTable();
    }

    /** How many field lines arrived as a reference into that table; see {@link #dynamicTable()}. */
    long dynamicTableReferences() {
        return qpack.getDynamicTableReferences();
    }

    /** The blocked stream limit the decoder was given, to check it against the one advertised. */
    int qpackMaxBlockedStreams() {
        return qpack.getMaxBlockedStreams();
    }

    /** The value this connection's SETTINGS frame carries for a setting, or zero if it carries none. */
    long advertised(long identifier) {
        Long value = settingsParameters.get(identifier);
        return value == null ? 0 : value;
    }

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
     * Writes the control stream and its SETTINGS frame as 0-RTT data, which is the first thing an
     * HTTP/3 connection has to say and the only thing it can say before the handshake finishes.
     * <p>
     * This is why kwik needed an early data API of its own: {@code connect(List&lt;StreamEarlyData&gt;)}
     * turns each element into a <em>bidirectional</em> stream, and the control stream is
     * unidirectional. If the server rejects the early data, kwik sends the same bytes again on the
     * same stream once the handshake completes, so there is nothing to undo here.
     */
    void sendControlStreamAsEarlyData(QuicClientConnection.EarlyDataSender sender) throws IOException {
        SettingsFrame settingsFrame = new SettingsFrame();
        settingsFrame.addParameters(settingsParameters);
        ByteBuffer serializedSettings = settingsFrame.getBytes();
        byte[] controlStream = new byte[1 + serializedSettings.limit()];
        controlStream[0] = STREAM_TYPE_CONTROL_STREAM;
        System.arraycopy(serializedSettings.array(), 0, controlStream, 1, serializedSettings.limit());
        // https://www.rfc-editor.org/rfc/rfc9114.html#name-control-streams
        // "The sender MUST NOT close the control stream"
        sender.send(false, controlStream, false);
        controlStreamSentAsEarlyData = true;
    }

    /**
     * Opens the QPACK decoder stream alongside flupke's control stream, which is where a connection's
     * unidirectional streams are opened and the first point at which the QUIC connection is up.
     * <p>
     * It cannot go through {@code createUnidirectionalStream}, which refuses the four stream types
     * RFC 9114 defines, so it is opened the way {@code startControlStream} opens its own.
     */
    @Override
    protected void startControlStream() {
        if (!controlStreamSentAsEarlyData) {
            super.startControlStream();
        }
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
     * Tells the decoder which stream the frame about to be read came in on, so that a field section
     * can be acknowledged by stream id as RFC 9204 section 4.4.1 requires. This is the last point
     * where both are in hand: flupke's {@code readHeadersFrame} is private and passes the decoder the
     * section's bytes and nothing else.
     */
    @Override
    protected Http3Frame readFrame(InputStream input, long maxHeadersSize, long maxDataSize) throws IOException, HttpError {
        qpack.setSectionStreamId(input instanceof StreamInputStream
                ? ((StreamInputStream) input).getStreamId()
                : null);
        return super.readFrame(input, maxHeadersSize, maxDataSize);
    }
}
