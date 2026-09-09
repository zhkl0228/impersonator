package com.github.zhkl0228.impersonator.quic;

import tech.kwik.core.QuicSessionTicket;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session tickets kept in memory for as long as the object lives, which is what a browser's own
 * cache amounts to: it is not written anywhere and it does not outlive the process.
 * <p>
 * Bounded per host, because a server hands out several tickets per connection and nothing here ever
 * asks it to stop. Oldest go first, tickets being interchangeable.
 */
public class InMemorySessionTicketStore implements SessionTicketStore {

    /** Chrome keeps a handful per host; more than this and the oldest are of no use anyway. */
    private static final int MAX_TICKETS_PER_HOST = 8;

    private final Map<String, Deque<QuicSessionTicket>> tickets = new ConcurrentHashMap<>();

    @Override
    public QuicSessionTicket take(String host) {
        Deque<QuicSessionTicket> forHost = tickets.get(host);
        if (forHost == null) {
            return null;
        }
        synchronized (forHost) {
            return forHost.pollFirst();
        }
    }

    @Override
    public void put(String host, List<QuicSessionTicket> newTickets) {
        if (newTickets == null || newTickets.isEmpty()) {
            return;
        }
        Deque<QuicSessionTicket> forHost = tickets.computeIfAbsent(host, key -> new ArrayDeque<>());
        synchronized (forHost) {
            forHost.addAll(newTickets);
            while (forHost.size() > MAX_TICKETS_PER_HOST) {
                forHost.pollFirst();
            }
        }
    }
}
