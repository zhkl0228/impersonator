package com.github.zhkl0228.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public interface ImpersonatorApi {

    SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

    /**
     * An {@link SSLContext} that accepts every server certificate, chain and expiry unchecked. Meant
     * for talking through an intercepting proxy whose CA is not installed, and for tests; a browser
     * validates the chain, so {@link #newSSLContext(KeyManager[], TrustManager[])} with no trust
     * manager of its own stays the right choice everywhere else. Client certificates go through
     * that method too; this one is only about not checking the server's.
     */
    SSLContext newTrustAnyCertificateSSLContext();

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
