package tech.kwik.core.impl;

import junit.framework.TestCase;
import tech.kwik.core.QuicClientConnection;

import java.net.URI;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * {@link QuicClientConnection#keepAliveEvery} against a real server: a connection pinged at an interval outlives its
 * idle timeout for as long as it is kept, and leaves no thread behind once closed.
 */
public class KeepAliveEveryTest extends TestCase {

    /** The project's own endpoint, as in {@link EarlyDataWindowTest}. */
    private static final URI ENDPOINT = URI.create("https://gzmtx.cn:8444");

    public void testAConnectionPingedAtAnIntervalOutlivesItsIdleTimeout() throws Exception {
        QuicClientConnection connection = connection(Duration.ofSeconds(2));
        try {
            connection.connect();
            connection.keepAliveEvery(Duration.ofMillis(500));
            TimeUnit.SECONDS.sleep(5);   // two and a half idle timeouts
            assertNull("the connection must still be up, but it ended: "
                            + ((QuicConnectionImpl) connection).getTerminationReason(),
                    ((QuicConnectionImpl) connection).getTerminationReason());
            assertTrue(connection.isConnected());
        }
        finally {
            connection.close();
        }
        for (int i = 0; i < 50 && keepAliveThreads() > 0; i++) {
            TimeUnit.MILLISECONDS.sleep(100);
        }
        assertEquals("the keep-alive thread must end with the connection", 0, keepAliveThreads());
    }

    public void testAnIntervalThatCannotHoldOffTheIdleTimeoutIsRefused() throws Exception {
        QuicClientConnection connection = connection(Duration.ofSeconds(2));
        try {
            connection.connect();
            connection.keepAliveEvery(Duration.ofSeconds(2));
            fail("a PING every idle timeout cannot keep the connection alive");
        }
        catch (IllegalArgumentException expected) {
            assertEquals("a PING every 2000ms cannot keep alive a connection that goes idle after 2000ms",
                    expected.getMessage());
        }
        finally {
            connection.close();
        }
    }

    public void testOnlyOnceConnected() throws Exception {
        QuicClientConnection connection = connection(Duration.ofSeconds(2));
        try {
            connection.keepAliveEvery(Duration.ofMillis(500));
            fail("nothing to keep alive before the connection is up");
        }
        catch (IllegalStateException expected) {
            assertEquals("keep alive can only be set when connected", expected.getMessage());
        }
        finally {
            connection.close();
        }
    }

    private static QuicClientConnection connection(Duration maxIdleTimeout) throws Exception {
        return QuicClientConnection.newBuilder()
                .uri(ENDPOINT)
                .applicationProtocol("h3")
                .noServerCertificateCheck()
                .maxIdleTimeout(maxIdleTimeout)
                .build();
    }

    private static long keepAliveThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().equals("kwik-keep-alive"))
                .count();
    }
}
