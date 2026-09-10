package tech.kwik.core.impl;

import junit.framework.TestCase;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.QuicSessionTicket;
import tech.kwik.core.QuicStream;
import tech.kwik.core.stream.EarlyDataStream;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.List;

/**
 * The 0-RTT window: the period between the ClientHello going out and the handshake finishing, in
 * which an ordinary {@code createStream} hands out a stream that writes 0-RTT data.
 * <p>
 * kwik had 0-RTT only through {@code connect(EarlyDataWriter)}, which blocks until the handshake is
 * over and gives the caller a sender that takes one complete flight per stream. That is enough for
 * data the caller has in hand and not enough for an HTTP request: flupke's {@code send()} takes a
 * stream from {@code createStream}, writes the request to it and then waits for the response on the
 * same thread, so inside a writer it would wait for a handshake its own thread is holding up. With
 * the window as a period rather than a callback, flupke needs to know nothing about 0-RTT - the
 * stream it asks for is already one.
 * <p>
 * That the bytes really leave in 0-RTT packets was read off ngtcp2's own server, which logs the
 * packet type each frame arrived in (docs/tools/README.md has the recipe). Writing this test's probe
 * string to a stream taken from {@code createStream(true)}:
 * <pre>
 *   pkt rx pkn=0 ... version=0x00000001 type=0RTT len=84
 *   frm rx 0 0RTT STREAM(0x0e) id=0x0 fin=0 offset=0 len=63 uni=0
 * </pre>
 * A bidirectional stream, id 0 - which is the stream an HTTP/3 request uses - carrying its bytes in
 * a 0-RTT packet, before the handshake was done.
 */
public class EarlyDataWindowTest extends TestCase {

    /**
     * The project's own endpoint, because this needs a server that reliably resumes: the public ones
     * accept a ticket they issued about as often as not, which cannot be told apart from a bug here.
     * See docs/tools/h3_field_echo.py, which keeps its tickets and takes every one back.
     */
    private static final URI ENDPOINT = URI.create("https://gzmtx.cn:8444");

    /**
     * A stream opened in the window writes at the 0-RTT level, and the server takes what it wrote.
     * <p>
     * Both halves matter. That the stream is an {@link EarlyDataStream} is what puts the bytes in
     * 0-RTT packets - its output stream is the only one that reports that encryption level - and that
     * the server answers "Accepted" is what says they arrived as 0-RTT rather than being quietly
     * held back until the handshake finished, which is what an ordinary stream would have done.
     */
    public void testAStreamOpenedInTheWindowSendsZeroRttData() throws Exception {
        QuicClientConnection connection = resuming();
        try {
            connection.startConnect(true);

            QuicStream stream = connection.createStream(true);
            assertTrue("a stream opened in the window must be one that writes at the 0-RTT level,"
                            + " got " + stream.getClass().getName(),
                    stream instanceof EarlyDataStream);

            OutputStream out = stream.getOutputStream();
            out.write("0-RTT window probe: this went out before the handshake finished".getBytes());
            out.flush();

            connection.awaitConnected();

            assertEquals("the server did not take the early data, so it was not sent as early data",
                    QuicClientConnectionImpl.EarlyDataStatus.Accepted,
                    ((QuicClientConnectionImpl) connection).getEarlyDataStatus());
        }
        finally {
            connection.close();
        }
    }

    /**
     * Outside the window nothing changes: a connection that has not started its handshake still has
     * no streams to give. The window is the whole of what was opened up, and it is only open to a
     * connection that is resuming and said it would send early data.
     */
    public void testAConnectionThatHasNotStartedStillHasNoStreams() throws Exception {
        QuicClientConnection connection = resuming();
        try {
            connection.createStream(true);
            fail("a connection that has not sent its ClientHello cannot open a stream");
        }
        catch (IOException expected) {
            assertEquals("not connected", expected.getMessage());
        }
        finally {
            connection.close();
        }
    }

    /**
     * Offering "early_data" and writing none is refused, which is the invariant the writer version
     * enforced by demanding the writer write something. A ClientHello that offers it and a connection
     * that sends nothing is a claim about this client that is not true.
     */
    public void testOfferingEarlyDataAndSendingNoneIsRefused() throws Exception {
        QuicClientConnection connection = resuming();
        try {
            connection.startConnect(true);
            connection.awaitConnected();
            fail("a connection that offered early data and wrote none must be refused");
        }
        catch (IllegalStateException expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("must write some"));
        }
        finally {
            connection.close();
        }
    }

    /** A connection carrying a ticket from an ordinary connection to the same endpoint. */
    private static QuicClientConnection resuming() throws Exception {
        QuicSessionTicket ticket = ticket();
        assertNotNull("the endpoint issued no session ticket, so there is nothing to resume", ticket);
        return QuicClientConnection.newBuilder()
                .uri(ENDPOINT)
                .applicationProtocol("h3")
                .noServerCertificateCheck()
                .sessionTicket(ticket)
                .build();
    }

    /** One ordinary connection, for the ticket a resumed one needs. */
    private static QuicSessionTicket ticket() throws Exception {
        QuicClientConnection connection = QuicClientConnection.newBuilder()
                .uri(ENDPOINT)
                .applicationProtocol("h3")
                .noServerCertificateCheck()
                .build();
        try {
            connection.connect();
            // The ticket comes after the handshake and is not tied to anything this end asked for,
            // so it is waited for rather than assumed to be in already.
            for (int i = 0; i < 100 && connection.getNewSessionTickets().isEmpty(); i++) {
                Thread.sleep(20);
            }
            List<QuicSessionTicket> tickets = connection.getNewSessionTickets();
            return tickets.isEmpty() ? null : tickets.get(0);
        }
        finally {
            connection.close();
        }
    }
}
