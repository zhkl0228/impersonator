package com.github.zhkl0228.impersonator.http3;

import tech.kwik.core.QuicConnection;
import tech.kwik.flupke.impl.Http3ClientConnectionImpl;

import java.util.Map;
import java.util.concurrent.ExecutorService;

/**
 * An HTTP/3 connection whose SETTINGS frame is the profile's rather than flupke's.
 * <p>
 * flupke sends two settings, both zero, and offers {@code addSettingsParameter} for adding more -
 * but it refuses to let the two it manages itself be changed, and it keeps them in a
 * {@code HashMap}, so neither their values nor the order they go out in are reachable that way.
 * The map is protected, though, so a subclass can put what the profile asked for straight into it.
 * <p>
 * That is a liberty taken with flupke's internals and it is taken narrowly: only the contents of
 * that one map, only in the constructor, before the control stream is opened. It is also the reason
 * flupke can stay an ordinary dependency rather than becoming a third vendored tree. If it ever
 * stops working, the failure is loud - the field is gone and this does not compile.
 * <p>
 * A profile may only ask for settings the implementation underneath honours; see
 * {@code Impersonator.getHttp3Settings()}.
 */
class Http3Connection extends Http3ClientConnectionImpl {

    Http3Connection(QuicConnection quicConnection, ExecutorService executorService, Map<Long, Long> settings) {
        super(quicConnection, executorService);
        if (settings != null) {
            settingsParameters.clear();
            settingsParameters.putAll(settings);
        }
    }
}
