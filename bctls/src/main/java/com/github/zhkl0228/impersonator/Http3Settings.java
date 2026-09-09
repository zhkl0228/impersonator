package com.github.zhkl0228.impersonator;

import java.util.concurrent.ThreadLocalRandom;

/**
 * The HTTP/3 SETTINGS identifiers of RFC 9114 and its extensions, for a profile to name rather than
 * spell in hex.
 * <p>
 * Declared here and not taken from flupke's {@code SettingsFrame}: that class is in flupke's
 * {@code impl} package, and flupke depends on kwik, which depends on agent15, which depends on this
 * module - naming it here would close a dependency cycle. It would also drag an HTTP/3 stack into
 * the module every plain HTTPS user already depends on. These are numbers from a registry, and the
 * registry is the source, not any implementation of it.
 */
public class Http3Settings {

    private Http3Settings() {
    }

    /** RFC 9204 section 5: the dynamic table capacity this endpoint's QPACK decoder will allow. */
    public static final long QPACK_MAX_TABLE_CAPACITY = 0x01;

    /** RFC 9114 section 7.2.4.1: the largest header list this endpoint will accept. */
    public static final long MAX_FIELD_SECTION_SIZE = 0x06;

    /** RFC 9204 section 5: how many streams this endpoint will let block on the dynamic table. */
    public static final long QPACK_BLOCKED_STREAMS = 0x07;

    /** RFC 9297 section 2.1.1: whether this endpoint accepts HTTP datagrams. */
    public static final long H3_DATAGRAM = 0x33;

    /**
     * RFC 9114 section 7.2.4.1: a reserved setting identifier, {@code 0x1f * N + 0x21}, which a peer
     * must ignore. Drawn afresh per connection, or it would be a stable identifier instead of noise.
     */
    public static long randomGrease() {
        return 0x1fL * ThreadLocalRandom.current().nextInt(1 << 24) + 0x21L;
    }
}
