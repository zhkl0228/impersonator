package com.github.zhkl0228.impersonator.quic;

import com.github.zhkl0228.impersonator.EchConfigProvider;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.QuicClientHello;
import com.github.zhkl0228.impersonator.QuicTransport;
import tech.kwik.agent15.TlsConstants;
import tech.kwik.agent15.ech.EchRejectedException;
import tech.kwik.core.QuicClientConnection;
import tech.kwik.core.crypto.InitialCryptoDivision;
import tech.kwik.core.send.PaddingMode;

import java.util.function.Supplier;

/**
 * Builds QUIC connections that impersonate a browser, the way {@code OkHttpClientFactory} builds
 * HTTP clients that do.
 * <p>
 * A profile belongs to a connection, not to a process: the ClientHello it dictates carries the
 * private halves of that connection's key shares, and an application may well want one profile for
 * one host and another for the next. So the factory hands out a
 * {@link QuicClientConnection.Builder} with the profile already on it, and every builder gets its
 * own state.
 *
 * <pre>
 * QuicClientFactory factory = QuicClientFactory.create(ImpersonatorFactory.macChrome());
 * QuicClientConnection connection = factory.newBuilder()
 *         .uri(URI.create("https://example.com"))
 *         .applicationProtocol("h3")
 *         .build();
 * </pre>
 */
public class QuicClientFactory {

    private final QuicClientHello quicClientHello;

    private SessionTicketStore sessionTicketStore = new InMemorySessionTicketStore();
    private NewTokenStore newTokenStore = new InMemoryNewTokenStore();

    /**
     * Asked once per connection rather than held as one object, because a profile draws part of its
     * answer afresh every time it is asked: the reserved transport parameter of RFC 9287 and the
     * reserved version of RFC 9368 are GREASE, and GREASE that is drawn once per factory is not
     * GREASE at all - it is a value that stays the same across every connection this factory opens,
     * which is a stable identifier rather than noise. The one place that already had this right is
     * {@link QuicTransport#getDestinationConnectionIdLength()}, which is a supplier for the same
     * reason.
     * <p>
     * A constant supplier for the two factory methods that are handed a {@link QuicTransport}: what a
     * caller built itself is theirs, and nothing here can redraw it.
     */
    private final Supplier<QuicTransport> quicTransport;

    private EchConfigProvider echConfigProvider;
    private EchRejectionHandler echRejectionHandler;

    private QuicClientFactory(QuicClientHello quicClientHello, Supplier<QuicTransport> quicTransport,
                              EchConfigProvider echConfigProvider) {
        this.quicClientHello = quicClientHello;
        this.quicTransport = quicTransport;
        this.echConfigProvider = echConfigProvider;
    }

    /**
     * @param api a profile from {@link ImpersonatorFactory}. It is an {@link ImpersonatorApi} there
     *            and an {@link Impersonator} here, the same object seen from the two sides.
     * @throws IllegalArgumentException if it is not one of this library's profiles.
     * @throws UnsupportedOperationException if no capture of this browser over HTTP/3 has been taken;
     *             see {@link Impersonator#getQuicClientHello()}.
     */
    public static QuicClientFactory create(ImpersonatorApi api) {
        if (!(api instanceof Impersonator)) {
            throw new IllegalArgumentException(api.getClass().getName() + " is not an "
                    + Impersonator.class.getName() + ", so it cannot describe a ClientHello");
        }
        Impersonator impersonator = (Impersonator) api;
        // The ClientHello is asked for now rather than per connection, so that a profile with no
        // HTTP/3 capture says so here. The transport is asked for per connection; see quicTransport.
        return new QuicClientFactory(impersonator.getQuicClientHello(), impersonator::getQuicTransport,
                impersonator::getEchConfigList);
    }

    /**
     * A ClientHello on its own, with no profile behind it and so no ECHConfigList source. For a
     * capture of something that is not one of this library's browsers.
     */
    public static QuicClientFactory create(QuicClientHello quicClientHello) {
        return create(quicClientHello, null);
    }

    /** A ClientHello and the QUIC layer that goes with it, with no profile behind them. */
    public static QuicClientFactory create(QuicClientHello quicClientHello, QuicTransport quicTransport) {
        if (quicClientHello == null) {
            throw new NullPointerException("quicClientHello");
        }
        return new QuicClientFactory(quicClientHello, () -> quicTransport, null);
    }

    /**
     * Connections that impersonate nothing: agent15's own ClientHello and no Encrypted Client Hello.
     * Useful as the control in a fingerprint comparison, and for plain QUIC.
     */
    public static QuicClientFactory create() {
        return new QuicClientFactory(null, () -> null, null);
    }

    /**
     * Replaces the profile's own source of ECHConfigLists, which is the DNS-over-HTTPS lookup a
     * browser does. Null turns Encrypted Client Hello off; unlike the TCP path there is no GREASE ECH
     * to fall back to, because no QUIC fingerprint is implemented yet.
     */
    public QuicClientFactory setEchConfigProvider(EchConfigProvider echConfigProvider) {
        this.echConfigProvider = echConfigProvider;
        return this;
    }

    /**
     * Called when a server rejects the ECHConfig that was offered, with the {@code retry_configs} it
     * published. RFC 9849 6.1.6 leaves retrying to the caller; nothing here retries.
     * <p>
     * A callback rather than something read off the failed connection because kwik reduces a TLS
     * error to a string and throws a fresh {@code ConnectException}, so the exception carrying the
     * retry configs never reaches the caller.
     */
    public QuicClientFactory setEchRejectionHandler(EchRejectionHandler echRejectionHandler) {
        this.echRejectionHandler = echRejectionHandler;
        return this;
    }

    /**
     * Where session tickets are kept between connections; see {@link SessionTicketStore}. It belongs
     * to the factory rather than to a connection because that is the scope a browser's ticket cache
     * has: one profile, every host it has visited.
     */
    public SessionTicketStore getSessionTicketStore() {
        return sessionTicketStore;
    }

    /**
     * Replaces the ticket store, or removes it - passing null turns resumption off, and every
     * connection is then a full handshake with the fingerprint that goes with it.
     */
    public QuicClientFactory setSessionTicketStore(SessionTicketStore sessionTicketStore) {
        this.sessionTicketStore = sessionTicketStore;
        return this;
    }

    /**
     * Where the address validation tokens from NEW_TOKEN frames are kept between connections; see
     * {@link NewTokenStore}. Same scope as the ticket store, and for the same reason: one profile,
     * every host it has visited.
     */
    public NewTokenStore getNewTokenStore() {
        return newTokenStore;
    }

    /**
     * Replaces the token store, or removes it - passing null means no connection ever carries a
     * token, and every one of them is a client whose address the server has not validated.
     */
    public QuicClientFactory setNewTokenStore(NewTokenStore newTokenStore) {
        this.newTokenStore = newTokenStore;
        return this;
    }

    /**
     * A builder with this factory's profile already on it. Each call gets its own, because a
     * ClientHello spec holds the private halves of one connection's key shares - and because the
     * profile's QUIC layer is drawn afresh here, GREASE and all; see {@link #quicTransport}.
     */
    public QuicClientConnection.Builder newBuilder() {
        QuicClientConnection.Builder builder = QuicClientConnection.newBuilder();
        if (quicClientHello != null) {
            builder.clientHelloSpec(new QuicClientHelloSpec(quicClientHello));
            /*
             * The profile decides what the ClientHello offers, so it also decides what may be
             * negotiated. Leaving kwik on its default of TLS_AES_128_GCM_SHA256 would offer three
             * suites and then refuse the server for choosing either of the other two. GREASE values
             * and anything this stack has no key schedule for are offered and not accepted, which is
             * what a peer does with them too.
             */
            for (int cipherSuite : quicClientHello.getCipherSuites()) {
                for (TlsConstants.CipherSuite known : TlsConstants.CipherSuite.values()) {
                    if ((known.value & 0xffff) == cipherSuite) {
                        builder.cipherSuite(known);
                    }
                }
            }
        }
        QuicTransport transport = quicTransport.get();
        if (transport != null) {
            applyTransport(builder, transport);
        }
        if (echConfigProvider != null) {
            builder.echConfigProvider(new tech.kwik.agent15.ech.EchConfigProvider() {
                @Override
                public byte[] getEchConfigList(String serverName) {
                    return echConfigProvider.getEchConfigList(serverName);
                }

                @Override
                public void echRejected(EchRejectedException rejection) {
                    if (echRejectionHandler != null) {
                        echRejectionHandler.echRejected(rejection.getServerName(), rejection.getPublicName(),
                                rejection.getRetryConfigs());
                    }
                }
            });
        }
        return builder;
    }


    /**
     * Everything the profile says about the QUIC layer goes through the builder, which is what makes
     * the connection behave the way it advertises: a flow control limit on the wire is a promise, and
     * setting it here sets both halves.
     */
    private void applyTransport(QuicClientConnection.Builder builder, QuicTransport quicTransport) {
        if (quicTransport.getDestinationConnectionIdLength() != null) {
            // Asked here, once per builder and so once per connection, which is what a browser that
            // draws a fresh length every time needs.
            builder.destinationConnectionIdLength(quicTransport.getDestinationConnectionIdLength().getAsInt());
        }
        if (quicTransport.getSourceConnectionIdLength() != null) {
            builder.connectionIdLength(quicTransport.getSourceConnectionIdLength());
        }
        builder.chaosProtection(quicTransport.isChaosProtection());
        if (quicTransport.isSniSlicing()) {
            builder.initialCryptoDivision(new InitialCryptoDivision.NeqoSniSlicing());
        }
        if (quicTransport.getInitialCryptoChunkSize() != null) {
            builder.initialCryptoDivision(
                    new InitialCryptoDivision.FixedChunks(quicTransport.getInitialCryptoChunkSize()));
        }
        if (quicTransport.isPaddingOutsidePacket()) {
            builder.paddingMode(PaddingMode.OUTSIDE);
        }
        if (quicTransport.getActiveConnectionIdLimit() != null) {
            builder.activeConnectionIdLimit(quicTransport.getActiveConnectionIdLimit());
        }
        if (quicTransport.getInitialDatagramSize() != null) {
            builder.initialDatagramSize(quicTransport.getInitialDatagramSize());
        }
        if (quicTransport.getInitialMaxData() != null) {
            builder.initialMaxData(quicTransport.getInitialMaxData());
        }
        if (quicTransport.getInitialMaxStreamDataBidirectional() != null) {
            builder.initialMaxStreamDataBidirectional(quicTransport.getInitialMaxStreamDataBidirectional());
        }
        if (quicTransport.getMaxAckDelayMillis() != null) {
            builder.maxAckDelay(quicTransport.getMaxAckDelayMillis());
        }
        if (quicTransport.getInitialMaxStreamDataBidirectionalRemote() != null) {
            builder.initialMaxStreamDataBidirectionalRemote(quicTransport.getInitialMaxStreamDataBidirectionalRemote());
        }
        if (quicTransport.getInitialMaxStreamDataUnidirectional() != null) {
            builder.initialMaxStreamDataUnidirectional(quicTransport.getInitialMaxStreamDataUnidirectional());
        }
        if (quicTransport.getInitialMaxStreamsBidirectional() != null) {
            builder.maxOpenPeerInitiatedBidirectionalStreams(quicTransport.getInitialMaxStreamsBidirectional());
        }
        if (quicTransport.getInitialMaxStreamsUnidirectional() != null) {
            builder.maxOpenPeerInitiatedUnidirectionalStreams(quicTransport.getInitialMaxStreamsUnidirectional());
        }
        if (quicTransport.getMaxIdleTimeoutMillis() != null) {
            builder.maxIdleTimeout(java.time.Duration.ofMillis(quicTransport.getMaxIdleTimeoutMillis()));
        }
        if (quicTransport.getMaxUdpPayloadSize() != null) {
            builder.maxUdpPayloadSize(quicTransport.getMaxUdpPayloadSize());
        }
        if (quicTransport.getMaxDatagramFrameSize() != null) {
            builder.maxDatagramFrameSize(quicTransport.getMaxDatagramFrameSize());
        }
        if (quicTransport.getAvailableVersions() != null) {
            builder.versionInformation(quicTransport.getAvailableVersions());
        }
        builder.addTransportParameters(quicTransport.getAddedParameters());
        builder.omitTransportParameters(quicTransport.getOmittedParameters());
    }
}
