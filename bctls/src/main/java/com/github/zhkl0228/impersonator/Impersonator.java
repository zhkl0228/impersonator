package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ClientHello;

import java.io.IOException;
import java.util.Map;

public interface Impersonator {

    /**
     * Whether a capture of this browser <em>resuming</em> a QUIC session exists, and so whether its
     * ClientHello description has a place for the "pre_shared_key" and "early_data" that a resumed
     * handshake adds.
     * <p>
     * False by default, and it means "not known" rather than "the browser cannot": a resumed
     * ClientHello is a different message with a different JA4, and putting the two extra extensions
     * somewhere plausible would produce a fingerprint the browser has never sent - worse than not
     * resuming, which at least sends one it does. Chrome says true because both of its ClientHellos
     * are in docs/captures; Safari will when a capture of it refreshing a page exists.
     */
    default boolean isQuicSessionResumptionSupported() {
        return false;
    }

    /**
     * The User-Agent of the impersonated browser, or null when there is none.
     */
    default String getUserAgent() {
        return null;
    }

    /**
     * The request headers the impersonated browser sends, in the order it sends them, added to the
     * map the caller passes in.
     * <p>
     * The caller seeds the map with the User-Agent first, because a profile moves that header rather
     * than supplying it - Chrome puts its client hints before it and the user agent after
     * Upgrade-Insecure-Requests, which it can only do to a header that is already there.
     * <p>
     * Declared here as well as on the TCP side because a browser is not only its handshake. A
     * connection whose QUIC, TLS and HTTP/3 fingerprints all match a browser exactly, carrying a
     * request with no User-Agent at all, is more obviously not a browser than a mismatched
     * fingerprint would be.
     */
    default void fillRequestHeaders(Map<String, String> headers) {
    }

    int[] getCipherSuites();

    int[] getKeyShareGroups();

    void onEstablishSession(Map<Integer, byte[]> clientExtensions) throws IOException;

    ExtensionOrder onSendClientHelloMessage(ClientHello clientHello, Map<Integer, byte[]> clientExtensions) throws IOException;

    /**
     * @return the ECHConfigList to offer for {@code host}, or null to send a GREASE ECH instead.
     */
    byte[] getEchConfigList(String host);

    /**
     * The ClientHello this profile sends over QUIC, for impersonator-quic to build agent15's
     * ClientHello from. A different capture from the TCP one; see {@link QuicClientHello}.
     *
     * @throws UnsupportedOperationException if no QUIC capture of this browser has been taken yet.
     *             Deriving one from the TCP ClientHello would send extensions no browser sends over
     *             QUIC, which is a fingerprint of its own.
     */
    default QuicClientHello getQuicClientHello() {
        throw new UnsupportedOperationException(getClass().getSimpleName()
                + " has no QUIC ClientHello; no capture of this browser over HTTP/3 has been taken");
    }

    /**
     * The QUIC layer of this profile: the transport parameters it sends and its connection id
     * lengths. A server reads these off the packet, separately from the ClientHello's JA4.
     *
     * @return the QUIC transport fingerprint, or null to keep the QUIC implementation's own, which is
     *         what a profile whose HTTP/3 capture covers only the ClientHello should say.
     */
    default QuicTransport getQuicTransport() {
        return null;
    }

    /**
     * The HTTP/3 SETTINGS this profile sends, in the order they go in the frame. A fresh map per
     * connection, because a GREASE setting has to be drawn per connection to be GREASE at all.
     * <p>
     * Which settings an endpoint sends, and with what values, is read as readily as a ClientHello.
     * But a setting is also a promise about what this end can do - QPACK_MAX_TABLE_CAPACITY invites
     * the peer to use a dynamic table - so a profile may only claim what the HTTP/3 implementation
     * underneath actually honours.
     *
     * @return the settings, or null to keep the implementation's own.
     */
    default Map<Long, Long> getHttp3Settings() {
        return null;
    }

}
