package com.github.zhkl0228.impersonator;

import org.bouncycastle.tls.ClientHello;

import java.io.IOException;
import java.util.Map;

public interface Impersonator {

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

}
