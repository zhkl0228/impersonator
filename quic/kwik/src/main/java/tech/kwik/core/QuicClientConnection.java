/*
 * Copyright © 2020, 2021, 2022, 2023, 2024, 2025, 2026 Peter Doornbosch
 *
 * This file is part of Kwik, an implementation of the QUIC protocol in Java.
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to support
 * Encrypted Client Hello (RFC 9849); see quic/UPSTREAM.md.
 */
package tech.kwik.core;

import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.ech.EchConfigProvider;
import tech.kwik.agent15.engine.ClientHelloSpec;

import java.util.Map;
import java.util.Set;
import tech.kwik.core.impl.QuicClientConnectionImpl;
import tech.kwik.core.log.Logger;

import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;


public interface QuicClientConnection extends QuicConnection {

    void connect() throws IOException;

    List<QuicStream> connect(List<StreamEarlyData> earlyData) throws IOException;

    /**
     * Connects while sending 0-RTT data the caller writes itself, which is what an application needs
     * when its first flight is not a list of bidirectional streams.
     * <p>
     * HTTP/3 is such an application: the first thing it sends is its control stream, which is
     * unidirectional, and its SETTINGS frame on it. {@link #connect(List)} can express neither.
     *
     * @param earlyDataWriter called after the ClientHello has gone out and before the handshake
     *                        completes, with a sender that opens 0-RTT streams. It must write
     *                        something: this connection has already told the server it is sending
     *                        early data, and a client that offers "early_data" and sends none is
     *                        making a claim about itself that is not true.
     * @return the streams the writer opened, in the order it opened them
     */
    List<QuicStream> connect(EarlyDataWriter earlyDataWriter) throws IOException;

    /**
     * Sends the ClientHello and returns, leaving the handshake to finish in the background;
     * {@link #awaitConnected()} waits for it.
     * <p>
     * Between the two, a connection that offered "early_data" is in its 0-RTT window: the streams
     * {@link QuicConnection#createStream(boolean)} hands out write at the 0-RTT level, so a library
     * that opens its own stream and writes a request to it - which is what HTTP/3 is - puts that
     * request in the first flight without knowing anything about 0-RTT.
     * <p>
     * {@link #connect(EarlyDataWriter)} is these two with a writer in between, and is enough when the
     * caller has the whole flight in hand. It is not enough for a request, because a writer runs
     * while the handshake is held up and a request is not finished until its response arrives.
     *
     * @param withEarlyData whether to offer "early_data" and write some. Offering it and writing
     *                      nothing is a claim about this client that is not true, so
     *                      {@link #awaitConnected()} refuses a connection that did.
     */
    void startConnect(boolean withEarlyData) throws IOException;

    /**
     * Waits for the handshake this connection started, and settles the 0-RTT data written while it
     * ran - which, when the server rejected it, means sending it again.
     */
    void awaitConnected() throws IOException;

    /** See {@link #connect(EarlyDataWriter)}. */
    interface EarlyDataWriter {
        void write(EarlyDataSender sender) throws IOException;
    }

    /** See {@link #connect(EarlyDataWriter)}. */
    interface EarlyDataSender {
        /**
         * Opens a stream and writes one flight of 0-RTT data on it. If the server rejects the early
         * data, the same bytes are sent again on the same stream once the handshake completes, so
         * the caller does not have to hold on to them.
         *
         * @param bidirectional false for a unidirectional stream, which is what HTTP/3's control and
         *                      QPACK streams are
         * @param closeOutput   whether the stream is finished by this flight
         * @return the stream, or null when the peer's remembered limits leave no credit for one
         */
        QuicStream send(boolean bidirectional, byte[] data, boolean closeOutput) throws IOException;
    }

    /**
     * Keeps the connection alive for {@code seconds} in total - not a PING every {@code seconds}: kwik pings at half
     * the idle timeout, and only while more than one such interval of the time is left, so anything up to half the
     * idle timeout sends nothing. For a PING at an interval for as long as the connection lives, see
     * {@link #keepAliveEvery}.
     */
    void keepAlive(int seconds);

    /**
     * Sends a PING every {@code interval} for as long as the connection lives, so a connection kept for reuse never
     * goes idle between uses. Only once connected, only once, and only with an interval shorter than the idle
     * timeout, which it could not otherwise hold off.
     */
    void keepAliveEvery(Duration interval);

    List<QuicSessionTicket> getNewSessionTickets();

    /**
     * Called with each session ticket as it arrives, rather than leaving a caller to ask afterwards.
     * <p>
     * {@link #getNewSessionTickets()} answers with what has arrived so far, which is enough for a
     * caller that asks once, at the end, and only if it gets that far. A connection that is kept -
     * which is what an HTTP client does, one per host for as long as it lives - has tickets and
     * tokens arriving throughout, and none of them is any use to anything else until somebody asks;
     * and a connection that is dropped rather than closed is never asked at all, so what it learned
     * is lost. A listener makes the two the same thing: the caller's store knows what the connection
     * knows, when it knows it.
     * <p>
     * It cannot conjure what has not arrived. A server that sends its NewSessionTicket after the
     * response has sent nothing by the time a caller that closes immediately has closed, and no
     * listener changes that - only staying connected does.
     * <p>
     * Set before connecting. It is called on the thread that processed the packet, so a listener that
     * blocks holds up the connection and one that throws ends it.
     *
     * @param listener the listener, or null to remove one.
     */
    void onNewSessionTicket(Consumer<QuicSessionTicket> listener);

    /** The same for the address validation tokens of NEW_TOKEN frames; see {@link #getNewTokens()}. */
    void onNewToken(Consumer<byte[]> listener);

    /**
     * The address validation tokens this connection was given in NEW_TOKEN frames, oldest first, for
     * a later connection to the same server to put in its Initial packets.
     * <p>
     * RFC 9000 section 8.1.3: "The server uses the NEW_TOKEN frame to provide the client with an
     * address validation token that can be used to validate future connections. In a future
     * connection, the client includes this token in Initial packets to provide address validation."
     * A client that keeps none is a client that never gets its address validated in advance, so it
     * is answered with a Retry where a browser is not - visibly, in the first datagram.
     * <p>
     * Only tokens from NEW_TOKEN frames: "The client MUST NOT use the token provided in a Retry for
     * future connections", so the one a Retry installed on this connection is not among these.
     *
     * @see Builder#initialToken(byte[])
     */
    List<byte[]> getNewTokens();

    /**
     * Whether this connection resumed an earlier session, the server having accepted the ticket it
     * was offered. See {@link tech.kwik.agent15.engine.TlsClientEngine#isSessionResumed()}: a
     * rejected ticket is not an error and not visible on the wire, it is just a full handshake.
     */
    boolean isSessionResumed();

    InetSocketAddress getLocalAddress();

    InetSocketAddress getServerAddress();

    List<X509Certificate> getServerCertificateChain();

    boolean isConnected();

    static Builder newBuilder() {
        return QuicClientConnectionImpl.newBuilder();
    }

    class StreamEarlyData {
        byte[] data;
        boolean closeOutput;

        public StreamEarlyData(byte[] data, boolean closeImmediately) {
            this.data = data;
            closeOutput = closeImmediately;
        }

        public byte[] getData() {
            return data;
        }

        public boolean isCloseOutput() {
            return closeOutput;
        }
    }

    interface Builder {

        QuicClientConnection build() throws SocketException, UnknownHostException;

        Builder applicationProtocol(String applicationProtocol);

        Builder connectTimeout(Duration duration);

        Builder maxIdleTimeout(Duration duration);

        Builder defaultStreamReceiveBufferSize(Long bufferSize);

        /**
         * The maximum number of peer initiated bidirectional streams that the peer is allowed to have open at any time.
         * If the value is 0, the peer is not allowed to open any bidirectional stream.
         * @param max
         * @return
         */
        Builder maxOpenPeerInitiatedBidirectionalStreams(int max);

        /**
         * The maximum number of peer initiated unidirectional streams that the peer is allowed to have open at any time.
         * If the value is 0, the peer is not allowed to open any unidirectional stream.
         * @param max
         * @return
         */
        Builder maxOpenPeerInitiatedUnidirectionalStreams(int max);

        Builder version(QuicVersion version);

        Builder initialVersion(QuicVersion version);

        Builder preferredVersion(QuicVersion version);

        /**
         * How this client divides its ClientHello between Initial packets; see
         * {@link tech.kwik.core.crypto.InitialCryptoDivision}. Null, the default, fills each packet
         * from the front until the data runs out, which is what kwik has always done and what no
         * browser does.
         */
        Builder initialCryptoDivision(tech.kwik.core.crypto.InitialCryptoDivision division);

        /**
         * Where the padding that brings an Initial datagram up to its size goes; see
         * {@link tech.kwik.core.send.PaddingMode}. Null, the default, keeps what the
         * {@code tech.kwik.padding-mode} system property asked for, which is PADDING frames inside
         * the packet.
         * <p>
         * A fingerprint, and one that survives every layer above it: Chrome and Safari fill their
         * Initial packets to the last byte of the datagram with PADDING frames, and Firefox ends its
         * packet where the CRYPTO frames end and pads the datagram after it with zeroes. A capture is
         * the only place this can be read - see docs/captures - but a server sees it in the first
         * datagram, and the fingerprint endpoint reports it as a padding length that Firefox does not
         * have.
         */
        Builder paddingMode(tech.kwik.core.send.PaddingMode paddingMode);

        Builder logger(Logger log);

        /**
         * An address validation token from a NEW_TOKEN frame on an earlier connection to this server,
         * which this connection then carries in every Initial packet it sends.
         * <p>
         * RFC 9000 section 8.1.3: "When connecting to a server for which the client retains an
         * applicable and unused token, it SHOULD include that token in the Token field of its Initial
         * packet", and "The client MUST include the token in all Initial packets it sends, unless a
         * Retry replaces the token with a newer one" - which is what receiving a Retry does here.
         * <p>
         * Null, the default, is a client with nothing to show, which is every kwik client until now
         * and no browser past its first connection to a host.
         *
         * @see QuicClientConnection#getNewTokens()
         */
        Builder initialToken(byte[] token);

        Builder sessionTicket(QuicSessionTicket ticket);

        Builder sessionTicket(byte[] ticketData);

        Builder proxy(String host);

        Builder secrets(Path secretsFile);

        Builder uri(URI uri);

        Builder host(String host);

        Builder port(int port);

        Builder preferIPv4();

        Builder preferIPv6();

        Builder connectionIdLength(int length);

        /**
         * Scrambles Initial packets the way Chrome does: the CRYPTO frames split into pieces sent out
         * of order, with PING frames and runs of PADDING between them. See
         * {@link tech.kwik.core.send.InitialPacketChaosProtector}, which explains why this belongs to
         * a profile rather than being done for every client - Chrome's QUIC does it and Firefox's and
         * Safari's do not.
         */
        Builder chaosProtection(boolean chaosProtection);

        /**
         * The size a datagram carrying an Initial packet is padded to. RFC 9000 section 14.1 requires
         * at least 1200 and what a client picks above that is one of the things it is recognized by:
         * Chrome sends 1250, Safari the bare 1200.
         */
        Builder initialDatagramSize(int size);

        /**
         * Length of the unpredictable Destination Connection ID the first Initial packet carries.
         * RFC 9000 only requires at least 8, so what an implementation picks above that is one of the
         * things a QUIC client is recognized by. Defaults to 8.
         */
        Builder destinationConnectionIdLength(int length);

        /** The initial_max_data transport parameter, and the connection level flow control it promises. */
        Builder initialMaxData(long initialMaxData);

        /**
         * The initial_max_stream_data_bidi_local and initial_max_stream_data_bidi_remote transport
         * parameters, and the per stream flow control they promise. kwik uses one value for both.
         */
        Builder initialMaxStreamDataBidirectional(long initialMaxStreamData);

        /**
         * The max_ack_delay transport parameter, in milliseconds. Absent means 25 to the peer, so
         * sending one at all is as visible as its value.
         */
        Builder maxAckDelay(int maxAckDelayInMillis);

        /**
         * The initial_max_stream_data_bidi_remote on its own, when it differs from the local one.
         * Firefox sends a smaller limit for streams the peer opens than for its own.
         */
        Builder initialMaxStreamDataBidirectionalRemote(long initialMaxStreamData);

        /** The initial_max_stream_data_uni transport parameter, and the flow control it promises. */
        Builder initialMaxStreamDataUnidirectional(long initialMaxStreamData);

        /**
         * The max_udp_payload_size transport parameter: the largest UDP payload this endpoint is
         * willing to receive.
         */
        Builder maxUdpPayloadSize(int maxUdpPayloadSize);

        /**
         * The active_connection_id_limit transport parameter. On Builder rather than only on
         * ExtendedBuilder, because which value a client sends - or whether it sends one at all - is a
         * fingerprint: Chrome omits it and Safari sends 64.
         */
        Builder activeConnectionIdLimit(int limit);

        /**
         * Leaves these transport parameters out of the extension rather than sending them with some
         * value. An absent parameter means its default to the peer, and which ones an endpoint
         * bothers to send is as much a fingerprint as the values; several implementations omit
         * anything that equals the default.
         *
         * @param omittedParameters {@link tech.kwik.core.QuicConstants.TransportParameterId} values.
         */
        Builder omitTransportParameters(Set<Integer> omittedParameters);

        /**
         * Appends transport parameters this implementation has no model of, as the bytes they should
         * carry, after the ones it does.
         * <p>
         * Only for parameters this endpoint does not act on - a GREASE parameter, or one belonging to
         * another implementation. A parameter that promises the peer something has to go through a
         * setter that also configures the connection to keep the promise, or the two drift apart.
         *
         * @param parameters parameter id to value, in the order they should be sent.
         */
        Builder addTransportParameters(Map<Integer, byte[]> parameters);

        /**
         * Sends the "version_information" of RFC 9368 listing these as the versions this endpoint
         * offers, alongside the one it chose. A reserved version among them is how an implementation
         * greases version negotiation.
         *
         * @param otherVersionIds the versions to offer besides the one in use. RFC 9368 section 3 has
         *                        the Available Versions field include the chosen version, so it is
         *                        appended if it is not already among these.
         */
        Builder versionInformation(int... otherVersionIds);

        /**
         * Offers a real Encrypted Client Hello (RFC 9849) on this connection, so that the server name
         * travels inside an encrypted ClientHelloInner instead of a plaintext SNI.
         *
         * @param echConfigProvider  supplies the ECHConfigList for the host, and hears about a rejection.
         */
        Builder echConfigProvider(EchConfigProvider echConfigProvider);

        /**
         * Dictates what the ClientHello looks like on this connection, so that it can be made to
         * resemble some other client's rather than agent15's own. A spec holds the private halves of
         * the key shares it generates, so it belongs to one connection and cannot be shared.
         *
         * @param clientHelloSpec  the spec, or null to let agent15 build the ClientHello it needs.
         */
        Builder clientHelloSpec(ClientHelloSpec clientHelloSpec);

        Builder initialRtt(int initialRtt);

        Builder cipherSuite(TlsConstants.CipherSuite cipherSuite);

        /**
         * Accepts any server certificate and any host name, which is what it says: there is then
         * nothing between this connection and whoever answers the address. Say it only where that is
         * what you mean - a test server, a host pinned some other way, a proxy of your own.
         */
        Builder noServerCertificateCheck();

        /**
         * Sets the custom trust store that will be used to validate the server's certificate.
         * If not set, the default trust store of the Java runtime environment will be used.
         * This is an alternative for calling {@link #customTrustManager(X509TrustManager)}, under the hood both
         * methods achieve the same result.
         * @param customTrustStore
         * @return  the builder
         */
        Builder customTrustStore(KeyStore customTrustStore);

        /**
         * Sets the custom trust manager that will be used to validate the server's certificate.
         * If not set, the default trust store of the Java runtime environment will be used.
         * This is an alternative for calling {@link #customTrustStore(KeyStore)}, under the hood both
         * methods achieve the same result.
         * @param customTrustManager
         * @return  the builder
         */
        Builder customTrustManager(X509TrustManager customTrustManager);

        Builder quantumReadinessTest(int nrOfDummyBytes);

        Builder clientCertificate(X509Certificate certificate);

        Builder clientCertificateKey(PrivateKey privateKey);

        /**
         * Sets the key manager that will be used to authenticate the client to the server. The key manager should
         * contain the client's private key(s) and certificate(s) it wants to use for authentication.
         * The first certificate whose issuer corresponds to one of the authorities indicated by the server is used.
         * If none matches or if the server did not send the "certificate_authorities" extension, the first certificate
         * in the key store is used.
         * @param   keyManager
         * @return  the builder
         */
        Builder clientKeyManager(X509ExtendedKeyManager keyManager);

        /**
         * Sets the key manager that will be used to authenticate the client to the server. The key manager should
         * contain the client's private key(s) and certificate(s) it wants to use for authentication.
         * The first certificate whose issuer corresponds to one of the authorities indicated by the server is used.
         * If none matches or if the server did not send the "certificate_authorities" extension, the first certificate
         * in the key store is used.
         * @param   keyManager
         * @return  the builder
         */
        Builder clientKeyManager(KeyStore keyManager);

        /**
         * Sets the password for the client's private key.
         * @param keyPassword
         * @return  the builder
         */
        Builder clientKey(String keyPassword);

        Builder socketFactory(DatagramSocketFactory socketFactory);

        /**
         * Enable the datagram extension (RFC 9221).
         * @return  the builder
         */
        Builder enableDatagramExtension();

        /**
         * Enables the datagram extension and advertises this max_datagram_frame_size, instead of the
         * value {@link #enableDatagramExtension()} picks. RFC 9221 leaves the value to the endpoint,
         * so what it advertises identifies it.
         */
        Builder maxDatagramFrameSize(int maxDatagramFrameSize);

        /**
         * Enable the Stream Resets with Partial Delivery extension
         * (https://www.ietf.org/archive/id/draft-ietf-quic-reliable-stream-reset-07.html)
         * @return  the builder
         */
        Builder enableReliableStreamReset();
    }

}
