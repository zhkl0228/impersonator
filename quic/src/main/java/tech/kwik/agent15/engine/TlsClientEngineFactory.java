package tech.kwik.agent15.engine;

import tech.kwik.agent15.engine.impl.TlsClientEngineImpl;

public class TlsClientEngineFactory {

    public static TlsClientEngine createClientEngine(ClientMessageSender clientMessageSender, TlsStatusEventHandler tlsStatusHandler) {
        return new TlsClientEngineImpl(clientMessageSender, tlsStatusHandler);
    }
}
