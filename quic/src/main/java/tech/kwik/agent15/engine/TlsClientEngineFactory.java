package tech.kwik.agent15.engine;

import tech.kwik.agent15.ech.EchConfigProvider;
import tech.kwik.agent15.engine.impl.TlsClientEngineImpl;

public class TlsClientEngineFactory {

    private static volatile EchConfigProvider defaultEchConfigProvider;

    /**
     * Sets the {@link EchConfigProvider} every client engine created from here on starts with, so
     * that Encrypted Client Hello can be turned on for a QUIC implementation that creates its TLS
     * engines itself and hands out no reference to them. An individual engine can still override it
     * with {@link TlsClientEngine#setEchConfigProvider}.
     * <p>
     * Process wide state is a fit here because an ECHConfigList belongs to a host and not to a
     * connection: the provider is asked per server name, and one instance answers for all of them.
     *
     * @param echConfigProvider the provider, or null to offer no Encrypted Client Hello at all.
     *
 * Modified for impersonator (https://github.com/zhkl0228/impersonator) to support
 * Encrypted Client Hello (RFC 9849); see quic/UPSTREAM.md.
 */
    public static void setDefaultEchConfigProvider(EchConfigProvider echConfigProvider) {
        defaultEchConfigProvider = echConfigProvider;
    }

    public static EchConfigProvider getDefaultEchConfigProvider() {
        return defaultEchConfigProvider;
    }

    public static TlsClientEngine createClientEngine(ClientMessageSender clientMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        TlsClientEngineImpl clientEngine = new TlsClientEngineImpl(clientMessageSender, tlsStatusHandler);
        clientEngine.setEchConfigProvider(defaultEchConfigProvider);
        return clientEngine;
    }
}
