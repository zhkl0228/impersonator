package com.github.zhkl0228.impersonator;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The QUIC layer of a profile's fingerprint: the transport parameters it sends and how long the
 * connection id in its first Initial packet is.
 * <p>
 * Separate from {@link QuicClientHello}, which is the TLS layer, because a server sees them
 * separately: the ClientHello gives a JA4, while these are read straight off the QUIC packet.
 * <p>
 * A transport parameter is a promise as much as a fingerprint - advertising a flow control limit
 * means honouring it - so these values are not written onto the wire and forgotten. They configure
 * the connection, and the wire follows.
 * <p>
 * Anything not set here keeps the QUIC implementation's own value. {@link #omit} is for the rest: an
 * absent parameter means its default to the peer, and which parameters an implementation bothers to
 * send is as much a giveaway as the values it sends.
 */
public class QuicTransport {

    /** Transport parameter ids of RFC 9000 section 18.2, for {@link Builder#omit}. */
    public static final int MAX_IDLE_TIMEOUT = 0x01;
    public static final int MAX_UDP_PAYLOAD_SIZE = 0x03;
    public static final int INITIAL_MAX_DATA = 0x04;
    public static final int INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = 0x05;
    public static final int INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = 0x06;
    public static final int INITIAL_MAX_STREAM_DATA_UNI = 0x07;
    public static final int INITIAL_MAX_STREAMS_BIDI = 0x08;
    public static final int INITIAL_MAX_STREAMS_UNI = 0x09;
    public static final int ACK_DELAY_EXPONENT = 0x0a;
    public static final int MAX_ACK_DELAY = 0x0b;
    public static final int DISABLE_ACTIVE_MIGRATION = 0x0c;
    public static final int ACTIVE_CONNECTION_ID_LIMIT = 0x0e;

    private final Integer destinationConnectionIdLength;
    private final Integer sourceConnectionIdLength;
    private final Long initialMaxData;
    private final Long initialMaxStreamDataBidirectional;
    private final Long initialMaxStreamDataUnidirectional;
    private final Integer initialMaxStreamsBidirectional;
    private final Integer initialMaxStreamsUnidirectional;
    private final Long maxIdleTimeoutMillis;
    private final Integer maxUdpPayloadSize;
    private final Integer maxDatagramFrameSize;
    private final Set<Integer> omitted;

    private QuicTransport(Builder builder) {
        this.destinationConnectionIdLength = builder.destinationConnectionIdLength;
        this.sourceConnectionIdLength = builder.sourceConnectionIdLength;
        this.initialMaxData = builder.initialMaxData;
        this.initialMaxStreamDataBidirectional = builder.initialMaxStreamDataBidirectional;
        this.initialMaxStreamDataUnidirectional = builder.initialMaxStreamDataUnidirectional;
        this.initialMaxStreamsBidirectional = builder.initialMaxStreamsBidirectional;
        this.initialMaxStreamsUnidirectional = builder.initialMaxStreamsUnidirectional;
        this.maxIdleTimeoutMillis = builder.maxIdleTimeoutMillis;
        this.maxUdpPayloadSize = builder.maxUdpPayloadSize;
        this.maxDatagramFrameSize = builder.maxDatagramFrameSize;
        this.omitted = Collections.unmodifiableSet(new LinkedHashSet<>(builder.omitted));
    }

    public static Builder newBuilder() {
        return new Builder();
    }

    /**
     * Length of the unpredictable Destination Connection ID in the first Initial packet, or null to
     * keep the implementation's own. RFC 9000 only requires at least 8, so what a client picks above
     * that identifies it.
     */
    public Integer getDestinationConnectionIdLength() {
        return destinationConnectionIdLength;
    }

    /** Length of the Source Connection ID this endpoint uses, or null for the implementation's own. */
    public Integer getSourceConnectionIdLength() {
        return sourceConnectionIdLength;
    }

    public Long getInitialMaxData() {
        return initialMaxData;
    }

    /** One value for both initial_max_stream_data_bidi_local and _bidi_remote. */
    public Long getInitialMaxStreamDataBidirectional() {
        return initialMaxStreamDataBidirectional;
    }

    public Long getInitialMaxStreamDataUnidirectional() {
        return initialMaxStreamDataUnidirectional;
    }

    public Integer getInitialMaxStreamsBidirectional() {
        return initialMaxStreamsBidirectional;
    }

    public Integer getInitialMaxStreamsUnidirectional() {
        return initialMaxStreamsUnidirectional;
    }

    public Long getMaxIdleTimeoutMillis() {
        return maxIdleTimeoutMillis;
    }

    public Integer getMaxUdpPayloadSize() {
        return maxUdpPayloadSize;
    }

    /**
     * The max_datagram_frame_size transport parameter, or null not to offer the datagram extension.
     */
    public Integer getMaxDatagramFrameSize() {
        return maxDatagramFrameSize;
    }

    /** The transport parameters to leave out of the extension entirely. */
    public Set<Integer> getOmittedParameters() {
        return omitted;
    }

    public static class Builder {

        private Integer destinationConnectionIdLength;
        private Integer sourceConnectionIdLength;
        private Long initialMaxData;
        private Long initialMaxStreamDataBidirectional;
        private Long initialMaxStreamDataUnidirectional;
        private Integer initialMaxStreamsBidirectional;
        private Integer initialMaxStreamsUnidirectional;
        private Long maxIdleTimeoutMillis;
        private Integer maxUdpPayloadSize;
        private Integer maxDatagramFrameSize;
        private final Set<Integer> omitted = new LinkedHashSet<>();

        public Builder destinationConnectionIdLength(int length) {
            this.destinationConnectionIdLength = length;
            return this;
        }

        public Builder sourceConnectionIdLength(int length) {
            this.sourceConnectionIdLength = length;
            return this;
        }

        public Builder initialMaxData(long initialMaxData) {
            this.initialMaxData = initialMaxData;
            return this;
        }

        public Builder initialMaxStreamDataBidirectional(long initialMaxStreamData) {
            this.initialMaxStreamDataBidirectional = initialMaxStreamData;
            return this;
        }

        public Builder initialMaxStreamDataUnidirectional(long initialMaxStreamData) {
            this.initialMaxStreamDataUnidirectional = initialMaxStreamData;
            return this;
        }

        public Builder initialMaxStreamsBidirectional(int max) {
            this.initialMaxStreamsBidirectional = max;
            return this;
        }

        public Builder initialMaxStreamsUnidirectional(int max) {
            this.initialMaxStreamsUnidirectional = max;
            return this;
        }

        /** The max_idle_timeout transport parameter, and the idle timeout the connection keeps. */
        public Builder maxIdleTimeoutMillis(long maxIdleTimeoutMillis) {
            this.maxIdleTimeoutMillis = maxIdleTimeoutMillis;
            return this;
        }

        /** The max_udp_payload_size transport parameter. */
        public Builder maxUdpPayloadSize(int maxUdpPayloadSize) {
            this.maxUdpPayloadSize = maxUdpPayloadSize;
            return this;
        }

        /** The max_datagram_frame_size transport parameter, i.e. RFC 9221's datagram extension. */
        public Builder maxDatagramFrameSize(int maxDatagramFrameSize) {
            this.maxDatagramFrameSize = maxDatagramFrameSize;
            return this;
        }

        /**
         * @param parameterIds RFC 9000 transport parameter ids, e.g. {@link #MAX_IDLE_TIMEOUT}, to
         *                     leave out of the extension rather than send with a value.
         */
        public Builder omit(int... parameterIds) {
            for (int parameterId : parameterIds) {
                omitted.add(parameterId);
            }
            return this;
        }

        public QuicTransport build() {
            return new QuicTransport(this);
        }
    }
}
