package tech.kwik.core.impl;

import junit.framework.TestCase;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicStream;
import tech.kwik.core.StreamClosedException;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * A stream cut off by its connection ending says how the connection ended. Production had a Hysteria2 request fail
 * 43ms in with {@code Connection closed (stream 8)} and nothing else, which cannot tell the peer closing the
 * connection from an idle timeout from this side closing it.
 */
public class StreamAbortReasonTest extends TestCase {

    /** The project's own endpoint, as in {@link EarlyDataWindowTest}. */
    private static final URI ENDPOINT = URI.create("https://gzmtx.cn:8444");

    public void testClosingTheConnectionIsNamedOnItsStreams() throws Exception {
        QuicClientConnection connection = connection(null);
        connection.connect();
        QuicStream stream = connection.createStream(true);
        connection.close();

        assertEquals("Connection closed (stream 0): closed (ImmediateClose)", readFailure(stream));
        assertEquals("output of stream 0 aborted because connection is closed: closed (ImmediateClose)",
                writeFailure(stream));
    }

    public void testAnIdleTimeoutIsNamedOnItsStreams() throws Exception {
        QuicClientConnection connection = connection(Duration.ofSeconds(1));
        try {
            connection.connect();
            QuicStream stream = connection.createStream(true);
            // The effective timeout is the smaller of the two sides', so this end's one second decides it.
            for (int i = 0; i < 100 && ((QuicConnectionImpl) connection).getTerminationReason() == null; i++) {
                TimeUnit.MILLISECONDS.sleep(100);
            }
            String reason = ((QuicConnectionImpl) connection).getTerminationReason();
            assertTrue("the connection must have timed out on its own, got " + reason,
                    "closed (IdleTimeout)".equals(reason) || "closed (ConnectionLost)".equals(reason));

            assertEquals("Connection closed (stream 0): " + reason, readFailure(stream));
            assertEquals("output of stream 0 aborted because connection is closed: " + reason, writeFailure(stream));
        }
        finally {
            connection.close();
        }
    }

    private static QuicClientConnection connection(Duration maxIdleTimeout) throws Exception {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder()
                .uri(ENDPOINT)
                .applicationProtocol("h3")
                .noServerCertificateCheck();
        if (maxIdleTimeout != null) {
            builder.maxIdleTimeout(maxIdleTimeout);
        }
        return builder.build();
    }

    private static String readFailure(QuicStream stream) {
        try {
            int read = stream.getInputStream().read(new byte[16]);
            fail("reading a stream of an ended connection must fail, got " + read);
            return null;
        }
        catch (StreamClosedException e) {
            return e.getMessage();
        }
        catch (IOException e) {
            throw new AssertionError("expected a StreamClosedException, got " + e, e);
        }
    }

    private static String writeFailure(QuicStream stream) {
        try {
            stream.getOutputStream().write(new byte[16]);
            fail("writing a stream of an ended connection must fail");
            return null;
        }
        catch (StreamClosedException e) {
            return e.getMessage();
        }
        catch (IOException e) {
            throw new AssertionError("expected a StreamClosedException, got " + e, e);
        }
    }
}
