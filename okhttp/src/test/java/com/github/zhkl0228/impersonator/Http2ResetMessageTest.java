package com.github.zhkl0228.impersonator;

import junit.framework.TestCase;
import okhttp3.OkHttpClient;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.internal.http2.ErrorCode;
import okhttp3.internal.http2.StreamResetException;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

/**
 * A GOAWAY fails the streams it cuts off as REFUSED_STREAM, whatever its own error code; the exception keeps
 * that code (callers retry on it) and says in its message what the peer actually sent.
 */
public class Http2ResetMessageTest extends TestCase {

    private static final int TYPE_HEADERS = 0x1;
    private static final int TYPE_RST_STREAM = 0x3;
    private static final int TYPE_SETTINGS = 0x4;
    private static final int TYPE_PING = 0x6;
    private static final int TYPE_GOAWAY = 0x7;
    private static final int TYPE_WINDOW_UPDATE = 0x8;
    private static final int FLAG_ACK = 0x1;
    private static final int FLAG_END_HEADERS = 0x4;

    public void testGoAwayCarriesItsOwnCodeAndDebugData() throws Exception {
        byte[] debug = "too_many_requests".getBytes(StandardCharsets.US_ASCII);
        ByteBuffer goAway = ByteBuffer.allocate(8 + debug.length);
        goAway.putInt(0).putInt(ErrorCode.ENHANCE_YOUR_CALM.getHttpCode()).put(debug);
        StreamResetException e = requestAgainst(TYPE_GOAWAY, 0, goAway.array());
        assertEquals(ErrorCode.REFUSED_STREAM, e.errorCode);
        assertEquals("stream was reset: REFUSED_STREAM (GOAWAY from peer: ENHANCE_YOUR_CALM, lastGoodStreamId=0,"
                + " this stream=3, debugData=\"too_many_requests\")", e.getMessage());
    }

    /**
     * The peer takes the request and never answers, not even a PING: the per-stream read timeout says so, on which
     * stream, what the peer sent after the stream opened, and that the connection itself went quiet.
     */
    public void testReadTimeoutNamesTheStreamAndPeer() throws Exception {
        String message = readTimeoutAgainst(false, false);
        assertTrue(message, message.matches("read timed out on stream 3 of 127\\.0\\.0\\.1 after 300ms;"
                + " after the stream opened the peer sent SETTINGS\\(stream 0, 0 bytes\\)\\+\\d+ms;"
                + " it did not answer a PING within 1000ms"));
    }

    /**
     * The peer acknowledges the request and answers a PING, but sends no response headers: the connection is
     * fine and the peer has the request, which the message says.
     */
    public void testReadTimeoutSaysThePeerStillAnswers() throws Exception {
        String message = readTimeoutAgainst(true, false);
        assertTrue(message, message.matches("read timed out on stream 3 of 127\\.0\\.0\\.1 after 300ms;"
                + " after the stream opened the peer sent SETTINGS\\(stream 0, 0 bytes\\)\\+\\d+ms,"
                + " WINDOW_UPDATE\\(stream 3, 4 bytes\\)\\+\\d+ms; it answered a PING in \\d+ms"));
    }

    /** The same for a body that stops coming after the response headers. */
    public void testBodyReadTimeoutSaysThePeerStillAnswers() throws Exception {
        String message = readTimeoutAgainst(true, true);
        assertTrue(message, message.matches("read timed out on stream 3 of 127\\.0\\.0\\.1 after 300ms;"
                + " after the stream opened the peer sent SETTINGS\\(stream 0, 0 bytes\\)\\+\\d+ms,"
                + " WINDOW_UPDATE\\(stream 3, 4 bytes\\)\\+\\d+ms, HEADERS\\(stream 3, 1 bytes\\)\\+\\d+ms;"
                + " it answered a PING in \\d+ms"));
    }

    /**
     * One h2c request against a peer that sends its SETTINGS only once the request is in, so every frame it
     * sends falls after the stream opened.
     *
     * @param answers         acknowledge the request with a WINDOW_UPDATE and answer PINGs; otherwise stay silent
     * @param responseHeaders send the response headers and then no body, so the body read times out instead
     * @return the read timeout's message
     */
    private static String readTimeoutAgainst(boolean answers, boolean responseHeaders) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread peer = new Thread(() -> {
                try (Socket s = server.accept()) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    OutputStream out = s.getOutputStream();
                    in.readFully(new byte[24]);                   // client connection preface
                    while (true) {
                        int[] header = readFrameHeader(in);
                        in.readFully(new byte[header[0]]);
                        if (header[1] == TYPE_HEADERS) {
                            break;
                        }
                    }
                    writeFrame(out, TYPE_SETTINGS, 0, 0, new byte[0]);
                    if (!answers) {
                        readUntilEof(in);                         // answer nothing, not even a PING
                        return;
                    }
                    writeFrame(out, TYPE_WINDOW_UPDATE, 0, 3, ByteBuffer.allocate(4).putInt(1).array());
                    if (responseHeaders) {
                        writeFrame(out, TYPE_HEADERS, FLAG_END_HEADERS, 3, new byte[]{(byte) 0x88}); // :status 200
                    }
                    while (true) {
                        int[] header = readFrameHeader(in);
                        byte[] payload = new byte[header[0]];
                        in.readFully(payload);
                        if (header[1] == TYPE_PING && (header[2] & FLAG_ACK) == 0) {
                            writeFrame(out, TYPE_PING, FLAG_ACK, 0, payload);
                        }
                    }
                } catch (IOException ignored) {
                    // the client hung up
                }
            }, "h2-peer");
            peer.setDaemon(true);
            peer.start();

            OkHttpClient client = new OkHttpClient.Builder()
                    .protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE))
                    .readTimeout(300, TimeUnit.MILLISECONDS)
                    .retryOnConnectionFailure(false)
                    .build();
            Request request = new Request.Builder().url("http://127.0.0.1:" + server.getLocalPort() + "/").build();
            try (Response response = client.newCall(request).execute()) {
                if (!responseHeaders) {
                    fail("expected the response headers to time out, got HTTP " + response.code());
                }
                response.body().string();
                fail("expected the body to time out");
                return null;
            } catch (java.net.SocketTimeoutException e) {
                return e.getMessage();
            } finally {
                client.dispatcher().executorService().shutdown();
                client.connectionPool().evictAll();
            }
        }
    }

    public void testRstStreamSaysItCameFromThePeer() throws Exception {
        byte[] rst = ByteBuffer.allocate(4).putInt(ErrorCode.REFUSED_STREAM.getHttpCode()).array();
        StreamResetException e = requestAgainst(TYPE_RST_STREAM, 3, rst);
        assertEquals(ErrorCode.REFUSED_STREAM, e.errorCode);
        assertEquals("stream was reset: REFUSED_STREAM (RST_STREAM from peer)", e.getMessage());
    }

    /** One h2c request; the server answers its HEADERS with a single frame of {@code type}. */
    private static StreamResetException requestAgainst(int type, int streamId, byte[] payload) throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread peer = new Thread(() -> {
                try (Socket s = server.accept()) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    OutputStream out = s.getOutputStream();
                    in.readFully(new byte[24]);                   // client connection preface
                    writeFrame(out, TYPE_SETTINGS, 0, 0, new byte[0]);
                    while (true) {
                        int[] header = readFrameHeader(in);
                        in.readFully(new byte[header[0]]);
                        if (header[1] == TYPE_HEADERS) {
                            writeFrame(out, type, 0, streamId, payload);
                            break;
                        }
                    }
                    readUntilEof(in);
                } catch (IOException ignored) {
                    // the client hung up
                }
            }, "h2-peer");
            peer.setDaemon(true);
            peer.start();

            OkHttpClient client = new OkHttpClient.Builder()
                    .protocols(Collections.singletonList(Protocol.H2_PRIOR_KNOWLEDGE))
                    .retryOnConnectionFailure(false)
                    .callTimeout(5, TimeUnit.SECONDS)
                    .build();
            Request request = new Request.Builder().url("http://127.0.0.1:" + server.getLocalPort() + "/").build();
            try (Response response = client.newCall(request).execute()) {
                fail("expected the stream to be reset, got HTTP " + response.code());
                return null;
            } catch (StreamResetException e) {
                return e;
            } finally {
                client.dispatcher().executorService().shutdown();
                client.connectionPool().evictAll();
            }
        }
    }

    private static void writeFrame(OutputStream out, int type, int flags, int streamId, byte[] payload) throws IOException {
        ByteBuffer frame = ByteBuffer.allocate(9 + payload.length);
        frame.put((byte) (payload.length >>> 16)).put((byte) (payload.length >>> 8)).put((byte) payload.length);
        frame.put((byte) type).put((byte) flags).putInt(streamId).put(payload);
        out.write(frame.array());
        out.flush();
    }

    /** {length, type, flags} */
    private static int[] readFrameHeader(DataInputStream in) throws IOException {
        byte[] h = new byte[9];
        in.readFully(h);
        int length = (h[0] & 0xff) << 16 | (h[1] & 0xff) << 8 | (h[2] & 0xff);
        return new int[]{length, h[3] & 0xff, h[4] & 0xff};
    }

    private static void readUntilEof(InputStream in) throws IOException {
        byte[] buf = new byte[1024];
        while (in.read(buf) != -1) {
            // drain
        }
    }
}
