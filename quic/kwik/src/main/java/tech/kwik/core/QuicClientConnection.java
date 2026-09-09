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


public interface QuicClientConnection extends QuicConnection {

    void connect() throws IOException;

    List<QuicStream> connect(List<StreamEarlyData> earlyData) throws IOException;

    void keepAlive(int seconds);

    List<QuicSessionTicket> getNewSessionTickets();

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

        Builder logger(Logger log);

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

        /** The initial_max_stream_data_uni transport parameter, and the flow control it promises. */
        Builder initialMaxStreamDataUnidirectional(long initialMaxStreamData);

        /**
         * The max_udp_payload_size transport parameter: the largest UDP payload this endpoint is
         * willing to receive.
         */
        Builder maxUdpPayloadSize(int maxUdpPayloadSize);

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
