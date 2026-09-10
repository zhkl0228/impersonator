package com.github.zhkl0228.impersonator.quic;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Address validation tokens kept in memory for as long as the object lives, which is what a
 * browser's own cache amounts to: it is not written anywhere and it does not outlive the process.
 * <p>
 * Bounded per host, because a server may send a token whenever it likes and nothing here asks it to
 * stop. The newest is taken and the oldest is dropped, which is the order RFC 9000 section 8.1.3
 * gives: "clients can regard older tokens as being less likely to be useful to the server for
 * address validation".
 */
public class InMemoryNewTokenStore implements NewTokenStore {

    /** Enough for the two or three a server sends per connection, and no use beyond that. */
    private static final int MAX_TOKENS_PER_HOST = 8;

    private final Map<String, Deque<byte[]>> tokens = new ConcurrentHashMap<>();

    @Override
    public byte[] take(String host) {
        Deque<byte[]> forHost = tokens.get(host);
        if (forHost == null) {
            return null;
        }
        synchronized (forHost) {
            return forHost.pollLast();
        }
    }

    @Override
    public void put(String host, List<byte[]> newTokens) {
        if (newTokens == null || newTokens.isEmpty()) {
            return;
        }
        Deque<byte[]> forHost = tokens.computeIfAbsent(host, key -> new ArrayDeque<>());
        synchronized (forHost) {
            forHost.addAll(newTokens);
            while (forHost.size() > MAX_TOKENS_PER_HOST) {
                forHost.pollFirst();
            }
        }
    }
}
