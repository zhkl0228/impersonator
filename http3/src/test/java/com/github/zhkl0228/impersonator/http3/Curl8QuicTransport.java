package com.github.zhkl0228.impersonator.http3;

import com.github.zhkl0228.impersonator.QuicTransport;

/**
 * The QUIC layer of curl 8.21.0 with ngtcp2, as reported by
 * {@code https://quic.tools.scrapfly.io/api/fp/quic} on 2026-09-09.
 * <pre>
 * dcid_length 20   scid_length 4
 * initial_max_data 1048576000
 * initial_max_stream_data_bidi_local 32768   bidi_remote 32768   uni 1048576000
 * initial_max_streams_bidi 262144   uni 262144
 * max_idle_timeout 0   max_udp_payload_size 2^62-1
 * ack_delay_exponent 3   max_ack_delay 25   active_connection_id_limit 2
 * </pre>
 * The last two lines are the values RFC 9000 gives an absent parameter, and 2^62-1 is what the
 * endpoint reports when {@code max_udp_payload_size} is missing, so what those really say is that
 * ngtcp2 sends nothing it does not have to. Hence the omissions rather than matching values.
 */
class Curl8QuicTransport {

    static QuicTransport create() {
        return QuicTransport.newBuilder()
                .destinationConnectionIdLength(20)
                .sourceConnectionIdLength(4)
                .initialMaxData(1048576000L)
                .initialMaxStreamDataBidirectional(32768L)
                .initialMaxStreamDataUnidirectional(1048576000L)
                .initialMaxStreamsBidirectional(262144)
                .initialMaxStreamsUnidirectional(262144)
                .omit(QuicTransport.MAX_IDLE_TIMEOUT, QuicTransport.MAX_UDP_PAYLOAD_SIZE)
                .build();
    }
}
