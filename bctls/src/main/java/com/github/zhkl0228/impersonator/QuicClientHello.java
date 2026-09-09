package com.github.zhkl0228.impersonator;

import java.io.IOException;
import java.util.Map;

/**
 * The ClientHello a profile sends over QUIC.
 * <p>
 * A separate description from {@link Impersonator#onSendClientHelloMessage}, because a browser's
 * QUIC ClientHello is not its TCP one: there is no "renegotiation_info" and no "session_ticket",
 * there is a "quic_transport_parameters", and "application_settings" names h3 rather than h2. The
 * two are different captures and this library does not invent one from the other.
 * <p>
 * Everything here is plain data - cipher suite values, named group values, extension bytes - so the
 * QUIC module can build agent15's ClientHello from it without a BouncyCastle handshake in sight.
 */
public interface QuicClientHello {

    /** Cipher suite values in wire order, GREASE included. */
    int[] getCipherSuites();

    /**
     * The named groups to send a key share for, in wire order. Every one of them gets a real
     * ephemeral, so a group naming a GREASE value does not belong here.
     */
    int[] getKeyShareGroups();

    /**
     * Fills in the extensions this profile sends and returns the order they go in, exactly as
     * {@link Impersonator#onSendClientHelloMessage} does for TCP.
     *
     * @param clientExtensions starts out holding what only the QUIC stack can supply - key_share,
     *                         quic_transport_parameters, ALPN - for the profile to add to.
     */
    ExtensionOrder onSendClientHelloMessage(Map<Integer, byte[]> clientExtensions) throws IOException;

}
