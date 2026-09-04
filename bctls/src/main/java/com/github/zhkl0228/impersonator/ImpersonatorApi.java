package com.github.zhkl0228.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.io.IOException;

public interface ImpersonatorApi {

    SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

    void setExtensionListener(ExtensionListener extensionListener);

    /**
     * Enables real Encrypted Client Hello. Hosts the provider has no ECHConfigList for keep sending
     * a GREASE ECH, exactly as a browser does.
     */
    void setEchConfigProvider(EchConfigProvider echConfigProvider);

    /**
     * Remembers what a server published when it rejected Encrypted Client Hello, so the next
     * connection to that host offers it instead of what the provider looks up. RFC 9849 section
     * 6.1.6.
     * <p>
     * Clients built by {@code OkHttpClientFactory} call this and retry once by themselves; it is
     * public for callers driving the handshake some other way. Pass only the configs from a
     * {@link org.bouncycastle.tls.TlsEchRejectedException}, which were read from a connection
     * authenticated for the ECHConfig's public_name.
     *
     * @param retryConfigs the server's {@code retry_configs}, or null if it published none, which
     *                     means Encrypted Client Hello is to be dropped for this host.
     * @throws IOException if the server offered nothing this library can use.
     */
    void onEchRejected(String host, byte[] retryConfigs) throws IOException;

}
