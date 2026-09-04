package com.github.zhkl0228.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public interface ImpersonatorApi {

    SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

    void setExtensionListener(ExtensionListener extensionListener);

    /**
     * Whether the impersonated browser does Encrypted Client Hello, and so whether
     * {@link #setEchConfigProvider(EchConfigProvider)} will accept a provider. Ask this rather than
     * keeping a list of which profiles do; the profile is what knows.
     */
    boolean isEchSupported();

    /**
     * Enables real Encrypted Client Hello. Hosts the provider has no ECHConfigList for keep sending
     * a GREASE ECH, exactly as a browser does.
     *
     * @throws UnsupportedOperationException if the impersonated browser does not do ECH, since
     *                                       offering one would put an extension in the ClientHello
     *                                       that the real browser never sends. Guard with
     *                                       {@link #isEchSupported()}.
     */
    void setEchConfigProvider(EchConfigProvider echConfigProvider);

}
