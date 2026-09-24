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
    private static final int TYPE_GOAWAY = 0x7;

    public void testGoAwayCarriesItsOwnCodeAndDebugData() throws Exception {
        byte[] debug = "too_many_requests".getBytes(StandardCharsets.US_ASCII);
        ByteBuffer goAway = ByteBuffer.allocate(8 + debug.length);
        goAway.putInt(0).putInt(ErrorCode.ENHANCE_YOUR_CALM.getHttpCode()).put(debug);
        StreamResetException e = requestAgainst(TYPE_GOAWAY, 0, goAway.array());
        assertEquals(ErrorCode.REFUSED_STREAM, e.errorCode);
        assertEquals("stream was reset: REFUSED_STREAM (GOAWAY from peer: ENHANCE_YOUR_CALM, lastGoodStreamId=0,"
                + " this stream=3, debugData=\"too_many_requests\")", e.getMessage());
    }

    /** The peer takes the request and never answers: the per-stream read timeout says so, and on which stream. */
    public void testReadTimeoutNamesTheStreamAndPeer() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread peer = new Thread(() -> {
                try (Socket s = server.accept()) {
                    DataInputStream in = new DataInputStream(s.getInputStream());
                    in.readFully(new byte[24]);
                    writeFrame(s.getOutputStream(), TYPE_SETTINGS, 0, 0, new byte[0]);
                    readUntilEof(in);       // take the request, answer nothing
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
                fail("expected the read to time out, got HTTP " + response.code());
            } catch (java.net.SocketTimeoutException e) {
                assertEquals("read timed out on stream 3 of 127.0.0.1 after 300ms", e.getMessage());
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

    /** {length, type} */
    private static int[] readFrameHeader(DataInputStream in) throws IOException {
        byte[] h = new byte[9];
        in.readFully(h);
        int length = (h[0] & 0xff) << 16 | (h[1] & 0xff) << 8 | (h[2] & 0xff);
        return new int[]{length, h[3] & 0xff};
    }

    private static void readUntilEof(InputStream in) throws IOException {
        byte[] buf = new byte[1024];
        while (in.read(buf) != -1) {
            // drain
        }
    }
}
