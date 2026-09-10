package com.github.zhkl0228.impersonator.quic;

import java.util.List;

/**
 * Where the address validation tokens a server hands out in NEW_TOKEN frames are kept between
 * connections, so that the next connection to the same host can put one in its Initial packets.
 * <p>
 * This is a fingerprint matter as much as a performance one, and of the same kind as never resuming.
 * A server under load answers an unvalidated client with a Retry, and RFC 9000 section 8.1.3 is what
 * lets a browser skip that: "In a future connection, the client includes this token in Initial
 * packets to provide address validation." A client that keeps no token asks for a Retry on every
 * connection where a browser asks for one only on its first - so the difference shows in the very
 * first datagram, both in the token field being empty and in the extra round trip that follows.
 * <p>
 * A token is taken out rather than looked up, because section 8.1.3 says it is used once: "A client
 * SHOULD NOT reuse a token from a NEW_TOKEN frame for different connection attempts. Reusing a token
 * allows connections to be linked by entities on the network path."
 *
 * @see SessionTicketStore the same arrangement for the TLS side of resuming
 */
public interface NewTokenStore {

    /**
     * Removes and returns a token for the host, or null when there is none.
     * <p>
     * The most recently issued one: "For a client, this ambiguity means that sending the most recent
     * unused token is most likely to be effective."
     *
     * @param host the host that issued it, which is the only one it may be sent to - "A client MUST
     *             NOT include a token that is not applicable to the server that it is connecting to"
     */
    byte[] take(String host);

    /**
     * Keeps the tokens a connection to the host was given, oldest first. The list may be empty, and
     * is for any server that does not do address validation for future connections at all.
     */
    void put(String host, List<byte[]> tokens);
}
