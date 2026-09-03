package com.github.zhkl0228.impersonator;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

public interface ImpersonatorApi {

    SSLContext newSSLContext(KeyManager[] km, TrustManager[] tm);

    void setExtensionListener(ExtensionListener extensionListener);

    /**
     * Enables real Encrypted Client Hello. Hosts the provider has no ECHConfigList for keep sending
     * a GREASE ECH, exactly as a browser does.
     */
    void setEchConfigProvider(EchConfigProvider echConfigProvider);

}
