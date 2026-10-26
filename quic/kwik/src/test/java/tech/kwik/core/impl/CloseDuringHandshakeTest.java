package tech.kwik.core.impl;

import junit.framework.TestCase;
import tech.kwik.core.QuicClientConnection;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * A connection closed while its handshake is still in Initial packets ends, its receiver and sender threads with it,
 * also when the server never answers. Closing it used to queue the end behind the next packet received, and from a
 * server that never answered none came: a web app kept such a connection's threads for days, and with them the class
 * loader of a version of itself redeployed since (gzsocks, 2026-10-26).
 */
public class CloseDuringHandshakeTest extends TestCase {

    public void testClosingBeforeTheServerAnswersEndsTheConnection() throws Exception {
        try (DatagramSocket silent = new DatagramSocket(0, InetAddress.getLoopbackAddress())) {
            QuicClientConnection connection = QuicClientConnection.newBuilder()
                    .uri(URI.create("https://127.0.0.1:" + silent.getLocalPort()))
                    .applicationProtocol("h3")
                    .connectTimeout(Duration.ofSeconds(60))
                    .noServerCertificateCheck()
                    .build();
            Thread connecting = new Thread(() -> {
                try {
                    connection.connect();
                }
                catch (IOException expected) {
                    // the close below ends the attempt
                }
            });
            connecting.setDaemon(true);
            connecting.start();
            // The first Initial packet is out: the handshake is under way and has nothing back
            silent.setSoTimeout(5000);
            silent.receive(new DatagramPacket(new byte[2048], 2048));

            connection.close();

            QuicConnectionImpl impl = (QuicConnectionImpl) connection;
            for (int i = 0; i < 100 && impl.connectionState != QuicConnectionImpl.Status.Closed; i++) {
                TimeUnit.MILLISECONDS.sleep(100);
            }
            assertEquals(QuicConnectionImpl.Status.Closed, impl.connectionState);
            connecting.join(TimeUnit.SECONDS.toMillis(5));
            assertFalse("connect() returns once the connection has ended", connecting.isAlive());
        }
    }
}
