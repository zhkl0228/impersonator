package com.github.zhkl0228.impersonator.quic;

import tech.kwik.core.QuicSessionTicket;

import java.util.List;

/**
 * Where the session tickets a server hands out are kept between connections, so that the next
 * connection to the same host can resume instead of doing a full handshake.
 * <p>
 * This is a fingerprint matter as much as a performance one. A browser resumes: after the first
 * visit, its connections to a host carry a "pre_shared_key" and its ClientHello is a different
 * message with a different JA4 - Chrome's fresh ClientHello has twelve extensions and its resumed
 * one has fourteen. A client that never resumes sends the same full handshake every time forever,
 * which is not a wrong fingerprint so much as an impossible history: no browser has ever visited a
 * site a hundred times without once presenting a ticket.
 * <p>
 * A ticket is taken out rather than looked up, because a ticket is used once. Reusing one across
 * connections is what makes 0-RTT replayable and is not what a browser does.
 */
public interface SessionTicketStore {

    /**
     * Removes and returns a ticket for the host, or null when there is none to resume with.
     *
     * @param host the host the ticket was issued by, which is the only thing it may be used for
     */
    QuicSessionTicket take(String host);

    /**
     * Keeps the tickets a connection to the host collected. The list may be empty, and usually is
     * until the handshake has been over for a moment - a server sends its NewSessionTickets after it,
     * not during it, so the right time to ask a connection for them is when it is done with.
     */
    void put(String host, List<QuicSessionTicket> tickets);
}
