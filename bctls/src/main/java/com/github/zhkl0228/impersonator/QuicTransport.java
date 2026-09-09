package com.github.zhkl0228.impersonator;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

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

    /** Google's {@code google_connection_options}, from Chromium's {@code transport_parameters.cc}. */
    public static final int GOOGLE_CONNECTION_OPTIONS = 0x3128;

    /**
     * A reserved QUIC version, RFC 9368 section 3: {@code 0x?a?a?a?a}, which no endpoint implements
     * and every endpoint must tolerate. Drawn afresh per connection.
     */
    public static int greaseVersion() {
        int version = 0;
        for (int i = 0; i < 4; i++) {
            version = (version << 8) | (ThreadLocalRandom.current().nextInt(16) << 4) | 0x0a;
        }
        return version;
    }

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
    private final Map<Integer, byte[]> added;
    private final int[] availableVersions;

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
        this.added = Collections.unmodifiableMap(new LinkedHashMap<>(builder.added));
        this.availableVersions = builder.availableVersions;
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

    /**
     * Transport parameters this library has no model of, as the bytes they carry, to append after the
     * ones it does.
     */
    public Map<Integer, byte[]> getAddedParameters() {
        return added;
    }

    /**
     * The Available Versions of the "version_information" parameter (RFC 9368), or null not to send
     * one. A reserved version among them is how an implementation greases version negotiation.
     */
    public int[] getAvailableVersions() {
        return availableVersions == null? null: availableVersions.clone();
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
        private final Map<Integer, byte[]> added = new LinkedHashMap<>();
        private int[] availableVersions;

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
         * A transport parameter this library has no model of, as the bytes it carries.
         * <p>
         * Only for parameters this endpoint does not act on. One that promises the peer something has
         * to go through a setter that also configures the connection to keep the promise.
         */
        public Builder parameter(int id, byte[] value) {
            added.put(id, value.clone());
            return this;
        }

        /**
         * Google's {@code google_connection_options} (0x3128), a list of four byte tags that turn on
         * QUIC experiments in Google's servers. Chrome sends {@code ORIG}, which asks for the HTTP/3
         * ORIGIN frame - "Experiment for sending new ORIGIN frame" in Chromium's
         * {@code crypto_protocol.h}. Receiving one is harmless: RFC 9114 has an endpoint ignore
         * frame types it does not know.
         */
        public Builder googleConnectionOptions(String... tags) {
            byte[] value = new byte[tags.length * 4];
            for (int i = 0; i < tags.length; i++) {
                byte[] tag = tags[i].getBytes(StandardCharsets.US_ASCII);
                if (tag.length != 4) {
                    throw new IllegalArgumentException("a connection option is a four byte tag, got \"" + tags[i] + "\"");
                }
                System.arraycopy(tag, 0, value, i * 4, 4);
            }
            return parameter(GOOGLE_CONNECTION_OPTIONS, value);
        }

        /**
         * A reserved transport parameter, RFC 9287: an id of the form {@code 31 * N + 27}, which a
         * peer must ignore. Drawn afresh per connection, or it would be a stable identifier instead of
         * noise.
         */
        public Builder greaseParameter() {
            int id = 31 * ThreadLocalRandom.current().nextInt(1 << 20) + 27;
            byte[] value = new byte[ThreadLocalRandom.current().nextInt(4)];
            ThreadLocalRandom.current().nextBytes(value);
            return parameter(id, value);
        }

        /**
         * Sends "version_information" (RFC 9368) offering these versions besides the one in use.
         * Section 3 has the Available Versions field include the chosen version, so the QUIC
         * implementation appends it; what belongs here is the rest, which for a browser is a reserved
         * version drawn per connection.
         *
         * @see #greaseVersion()
         */
        public Builder availableVersions(int... versionIds) {
            this.availableVersions = versionIds.clone();
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
