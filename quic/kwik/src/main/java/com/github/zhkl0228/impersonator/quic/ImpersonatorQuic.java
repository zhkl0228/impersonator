package com.github.zhkl0228.impersonator.quic;

import com.github.zhkl0228.impersonator.EchConfigProvider;
import com.github.zhkl0228.impersonator.Impersonator;
import com.github.zhkl0228.impersonator.ImpersonatorApi;
import com.github.zhkl0228.impersonator.ImpersonatorFactory;
import com.github.zhkl0228.impersonator.QuicClientHello;
import tech.kwik.agent15.ech.EchRejectedException;
import tech.kwik.agent15.engine.TlsClientEngineFactory;

/**
 * Turns on Encrypted Client Hello (RFC 9849) for QUIC, using the same
 * {@link EchConfigProvider} the TCP path takes through
 * {@code ImpersonatorApi.setEchConfigProvider}.
 * <p>
 * It is installed process wide rather than per connection because kwik creates its TLS engines
 * itself and hands out no reference to them. That is no loss: an ECHConfigList belongs to a host
 * and not to a connection, and the provider is asked per server name.
 *
 * <pre>
 * ImpersonatorQuic.setEchConfigProvider(EchConfigs.shared(), EchConfigs.shared()::recordRejection);
 * </pre>
 *
 * A host the provider answers null for gets a plain ClientHello with a visible SNI. Note that this
 * differs from the TCP path, which sends a GREASE ECH in that case because the browser it
 * impersonates does; QUIC fingerprinting is not implemented yet.
 */
public class ImpersonatorQuic {

    private ImpersonatorQuic() {
    }

    /**
     * Makes every QUIC ClientHello from here on look like this profile's, instead of like agent15's.
     * <p>
     * {@link ImpersonatorFactory#macChrome()} and friends return an {@link ImpersonatorApi}, so a
     * caller reaching the profile's ClientHello casts, the same as it does for the other hooks that
     * live on the profile rather than on the API:
     *
     * <pre>
     * ImpersonatorQuic.setImpersonator((Impersonator) ImpersonatorFactory.macChrome());
     * </pre>
     *
     * @param impersonator the profile, or null to go back to agent15's own ClientHello.
     * @throws UnsupportedOperationException if no capture of this browser over HTTP/3 has been taken;
     *             see {@link Impersonator#getQuicClientHello()}.
     */
    public static void setImpersonator(Impersonator impersonator) {
        setQuicClientHello(impersonator == null? null: impersonator.getQuicClientHello());
    }

    /**
     * The same, from a {@link QuicClientHello} on its own rather than from a profile.
     *
     * @param quicClientHello the ClientHello to send, or null to go back to agent15's own.
     */
    public static void setQuicClientHello(QuicClientHello quicClientHello) {
        if (quicClientHello == null) {
            TlsClientEngineFactory.setDefaultClientHelloSpec(null);
            return;
        }
        // One spec per connection: it holds the private halves of the key shares it generated.
        TlsClientEngineFactory.setDefaultClientHelloSpec(() -> new QuicClientHelloSpec(quicClientHello));
    }

    /**
     * @param echConfigProvider supplies the ECHConfigList per host, or null to send no Encrypted
     *                          Client Hello at all.
     */
    public static void setEchConfigProvider(EchConfigProvider echConfigProvider) {
        setEchConfigProvider(echConfigProvider, null);
    }

    /**
     * @param echConfigProvider supplies the ECHConfigList per host, or null to send no Encrypted
     *                          Client Hello at all.
     * @param echRejectionHandler told when a server rejects what was offered, with the
     *                          {@code retry_configs} it published. May be null, in which case a
     *                          rejection only fails the connection; the handshake error carries the
     *                          public name and the retry configs in hex.
     */
    public static void setEchConfigProvider(EchConfigProvider echConfigProvider, EchRejectionHandler echRejectionHandler) {
        if (echConfigProvider == null) {
            TlsClientEngineFactory.setDefaultEchConfigProvider(null);
            return;
        }
        TlsClientEngineFactory.setDefaultEchConfigProvider(new tech.kwik.agent15.ech.EchConfigProvider() {
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

}
