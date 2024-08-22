/* WolfSSLContext.java
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

package com.wolfssl.provider.jsse;

import java.io.ByteArrayOutputStream;
import java.security.KeyManagementException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.Arrays;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSL.TLS_VERSION;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * wolfSSL implementation of SSLContextSpi
 * @author wolfSSL
 */
public class WolfSSLContext extends SSLContextSpi {

    private TLS_VERSION currentVersion = TLS_VERSION.SSLv23;
    private WolfSSLAuthStore authStore = null;
    private com.wolfssl.WolfSSLContext ctx = null;
    private WolfSSLParameters params = null;

    private WolfSSLContext(TLS_VERSION version) {
        this.currentVersion = version;
    }

    private void createCtx() throws WolfSSLException {
        long method;
        String[] ciphersIana = null;

        /* Enable native wolfSSL debug logging if 'wolfssl.debug'
         * System property is set. Also attempted in WolfSSLProvider
         * but System property may not have been set by user yet at that
         * point. */
        WolfSSLDebug.setNativeWolfSSLDebugging();

        /* Get available wolfSSL cipher suites in IANA format */
        ciphersIana = WolfSSL.getCiphersAvailableIana(this.currentVersion);

        /* Allow ability for user to hard-code and override version, cipher
         * suite, and NO_* disable options. Otherwise just sets defaults
         * into ctxAttr. */
        WolfSSLCustomUser ctxAttr = WolfSSLCustomUser.GetCtxAttributes
                          (this.currentVersion, ciphersIana);

        /* Explicitly set SSLContext version if overridden by
         * WolfSSLCustomUser or specific SSLContext version was created
         * by user. Otherwise use default of SSLv23. Starts at highest TLS
         * protocol version supported by native wolfSSL then downgrades to
         * minimum native downgrade version. */
        if(ctxAttr.version == TLS_VERSION.TLSv1   ||
           ctxAttr.version == TLS_VERSION.TLSv1_1 ||
           ctxAttr.version == TLS_VERSION.TLSv1_2 ||
           ctxAttr.version == TLS_VERSION.TLSv1_3 ||
           ctxAttr.version == TLS_VERSION.SSLv23) {
            this.currentVersion = ctxAttr.version;
        } else {
            throw new IllegalArgumentException(
                "Invalid SSL/TLS protocol version");
        }

        /* Set SSLContext version. To be compatible with SunJSSE behavior,
         * the enabled protocols are less than or equal to the version
         * selected */
        switch (this.currentVersion) {
            case TLSv1:
                method = WolfSSL.TLSv1_Method();
                ctxAttr.noOptions = ctxAttr.noOptions |
                    WolfSSL.SSL_OP_NO_TLSv1_1 | WolfSSL.SSL_OP_NO_TLSv1_2 |
                    WolfSSL.SSL_OP_NO_TLSv1_3;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "creating WolfSSLContext with TLSv1");
                break;
            case TLSv1_1:
                method = WolfSSL.TLSv1_1_Method();
                ctxAttr.noOptions = ctxAttr.noOptions |
                    WolfSSL.SSL_OP_NO_TLSv1_2 | WolfSSL.SSL_OP_NO_TLSv1_3;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "creating WolfSSLContext with TLSv1_1");
                break;
            case TLSv1_2:
                method = WolfSSL.TLSv1_2_Method();
                ctxAttr.noOptions = ctxAttr.noOptions |
                    WolfSSL.SSL_OP_NO_TLSv1_3;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "creating WolfSSLContext with TLSv1_2");
                break;
            case TLSv1_3:
                method = WolfSSL.TLSv1_3_Method();
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "creating WolfSSLContext with TLSv1_3");
                break;
            case SSLv23:
                method = WolfSSL.SSLv23_Method();
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "creating WolfSSLContext with SSLv23");
                break;
            default:
                throw new IllegalArgumentException(
                    "Invalid SSL/TLS protocol version");
        }

        if (method == WolfSSL.NOT_COMPILED_IN) {
            throw new IllegalArgumentException("Protocol version not " +
                "compiled into native wolfSSL library");
        }
        ctx = new com.wolfssl.WolfSSLContext(method);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "created new native WOLFSSL_CTX");

        if(ctxAttr.list != null && ctxAttr.list.length > 0) {
            ciphersIana = ctxAttr.list;
        } else {
            ciphersIana = WolfSSL.getCiphersIana();
        }

        /* Set minimum allowed RSA/DH/ECC key sizes */
        enforceKeySizeLimitations();

        /* Set native wolfSSL device ID (devId) */
        setGlobalCryptoCallbackDevId();

        /* Auto-populate enabled ciphersuites with supported ones. If suites
         * have been restricted with wolfjsse.enabledCipherSuites system
         * security property, the suite list will be filtered in
         * WolfSSLEngineHelper.sanitizeSuites() to adhere to any
         * set restrictions */
        if (WolfSSLUtil.isSecurityPropertyStringSet(
            "wolfjsse.enabledCipherSuites")) {
            /* User is overriding cipher suites, set CTX list */
            this.setCtxCiphers(WolfSSLUtil.sanitizeSuites(ciphersIana));
        }
        params.setCipherSuites(WolfSSLUtil.sanitizeSuites(ciphersIana));

        /* Auto-populate enabled protocols with supported ones. Protocols
         * which have been disabled via system property get filtered in
         * WolfSSLEngineHelper.sanitizeProtocols() */
        params.setProtocols(WolfSSLUtil.sanitizeProtocols(
            this.getProtocolsMask(ctxAttr.noOptions)));

        try {
            LoadTrustedRootCerts();

        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Set native wolfSSL crypto callback device ID (devId).
     * The devId used defaults to WolfSSL.INVALID_DEVID but an app may
     * have set this globally via WolfSSLProvider.setDevId(). If not set
     * globally, applications may also set this via
     * SSLContext.setDevId() and SSLSocket.setDevId()
     *
     * @throws IllegalStateException if underlying WOLFSSL has been freed
     * @throws WolfSSLException if native wolfSSL/JNI error occurs
     */
    private void setGlobalCryptoCallbackDevId() throws WolfSSLException {
        int ret = 0;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "setting wolfSSL devId: " + WolfSSL.devId);

        try {
            ret = this.ctx.setDevId(WolfSSL.devId);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException(
                    "Error setting native wolfSSL device ID, ret = " + ret);
            }
        } catch (IllegalStateException e) {
            throw new WolfSSLException(e);
        }
    }

    /**
     * Set native WOLFSSL_CTX cipher suite list.
     * Converts String[] to colon-delimited cipher suite array, then
     * calls native wolfSSL_CTX_set_cipher_list().
     */
    private void setCtxCiphers(String[] suites)
            throws IllegalArgumentException {
        try {
            String list;
            StringBuilder sb = new StringBuilder();

            if (suites == null || suites.length == 0) {
                /* use default cipher suites */
                return;
            }

            for (String s : suites) {
                sb.append(s);
                sb.append(":");
            }

            if (sb.length() > 0) {
                /* remove last : */
                sb.deleteCharAt(sb.length() - 1);
                list = sb.toString();
                if (this.ctx.setCipherList(list) != WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "error setting WolfSSLContext cipher list: " +
                            list);
                }
            }

        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Set minimum supported key sizes for RSA/DH/ECC based on values
     * set by user in jdk.tls.disabledAlgorithms security property.
     *
     * @throws WolfSSLException Key size limitation fails to set in CTX
     */
    private void enforceKeySizeLimitations() throws WolfSSLException {

        int minKeySize = 0;
        int ret = 0;

        minKeySize = WolfSSLUtil.getDisabledAlgorithmsKeySizeLimit("RSA");
        ret = this.ctx.setMinRSAKeySize(minKeySize);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting SSLContext min RSA key size");
        }

        minKeySize = WolfSSLUtil.getDisabledAlgorithmsKeySizeLimit("EC");
        ret = this.ctx.setMinECCKeySize(minKeySize);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting SSLContext min ECC key size");
        }

        minKeySize = WolfSSLUtil.getDisabledAlgorithmsKeySizeLimit("DH");
        ret = this.ctx.setMinDHKeySize(minKeySize);
        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting SSLContext min DH key size");
        }
    }

    private void LoadTrustedRootCerts() {

        int ret = 0;
        int loadedCACount = 0;

        /* extract root certs from X509TrustManager */
        X509TrustManager tm = authStore.getX509TrustManager();

        if (tm == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "internal TrustManager is null, no CAs to load");
            return;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Using X509TrustManager: " + tm.toString());

        /* We only need to load trusted CA certificates into our native
         * WOLFSSL_CTX if we are doing internal verification with wolfSSL
         * native verify logic. Otherwise, the registered Java TrustManager
         * being used will handle verification (including CA lookup) when
         * we call checkClientTrusted()/checkServerTrusted().
         *
         * If tm is not an instance of WolfSSLTrustX509, simply return
         * here since we do not need to interface with native verification */
        if (!(tm instanceof com.wolfssl.provider.jsse.WolfSSLTrustX509)) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Deferring verification to checkClientTrusted/ServerTrusted()");
            return;
        }

        /* Get trusted/accepted root certificates from the X509TrustManager */
        X509Certificate[] caList =  tm.getAcceptedIssuers();
        if (caList == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "internal TrustManager has no accepted issuers to load");
            return;
        }

        if (caList.length == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "internal TrustManager has no certs");
            return;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Number of certs in X509TrustManager: " + caList.length);

        /* Load accepted issuer certificates into native WOLFSSL_CTX to be
         * used in native wolfSSL verify logic */
        for (int i = 0; i < caList.length; i++) {

            try {
                byte[] derCert = caList[i].getEncoded();

                ret = ctx.loadVerifyBuffer(derCert, derCert.length,
                                           WolfSSL.SSL_FILETYPE_ASN1);

                if (ret == WolfSSL.SSL_SUCCESS) {
                    loadedCACount++;
                } else {
                    /* skip loading on failure, move to next */
                    continue;
                }

            } catch (CertificateEncodingException ce) {
                /* skip loading if encoding error is encountered */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "skipped loading CA, encoding error");
            } catch (WolfSSLJNIException we) {
                /* skip loading if wolfSSL fails to load der encoding */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "skipped loading CA, JNI exception");
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "loaded trusted root cert (" + caList[i].getSigAlgName()
                    + "): " + caList[i].getSubjectX500Principal().getName(
                    X500Principal.RFC1779));
        }

        if (caList.length > 0 && loadedCACount == 0) {
            throw new IllegalArgumentException("wolfSSL failed to load " +
                "any trusted CA certificates from TrustManager");
        }
    }

    /**
     * Initializes a SSLContext.
     *
     * wolfJSSE currently selects the first KeyManager and TrustManager
     * in the input arrays to be used during the SSL/TLS context setup
     * and session. Native wolfSSL gets entropy directly based on how
     * the wolfSSL library has been compiled.  SecureRandom is not used
     * by wolfJSSE.
     *
     * @param km - array of KeyManager objects
     * @param tm - array of TrustManager objects
     * @param sr - SecureRandom object
     *
     * @throws KeyManagementException if wolfJSSE fails to load and use
     * input objects.
     */
    @Override
    protected void engineInit(KeyManager[] km, TrustManager[] tm,
        SecureRandom sr) throws KeyManagementException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineInit(km=" + km + ", tm=" + tm + ", sr=" + sr +")");

        try {
            authStore = new WolfSSLAuthStore(km, tm, sr, currentVersion);
            params = new WolfSSLParameters();
            createCtx();

        } catch (IllegalArgumentException iae) {
            throw new KeyManagementException(iae);

        } catch (WolfSSLException we) {
            throw new KeyManagementException(we);
        }
    }

    /**
     * Creates a new wolfJSSE SSLSocketFactory.
     *
     * @throws IllegalStateException if SSLContext has not been initialized
     */
    @Override
    protected SSLSocketFactory engineGetSocketFactory()
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetSocketFactory()");

        if (this.ctx == null || this.authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        return new WolfSSLSocketFactory(this.ctx, this.authStore, this.params);
    }

    /**
     * Creates a new wolfJSSE SSLServerSocketFactory.
     *
     * @throws IllegalStateException if SSLContext has not been initialized
     */
    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory()
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetServerSocketFactory()");

        if (this.ctx == null || this.authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        return new WolfSSLServerSocketFactory(this.ctx, this.authStore,
            this.params);
    }

    /**
     * Creates a new wolfJSSE SSLEngine.
     *
     * @throws IllegalStateException if SSLContext has not been initialized
     */
    @Override
    protected SSLEngine engineCreateSSLEngine()
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineCreateSSLEngine()");

        if (this.ctx == null || this.authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine(this.ctx, this.authStore, this.params);
        } catch (WolfSSLException ex) {
            throw new IllegalStateException("Unable to create engine");
        }
    }

    /**
     * Creates a new SSLEngine, using peer information as hints.
     *
     * @param host - name of the peer host
     * @param port - peer port
     *
     * @throws IllegalStateException if SSLContext has not been initialized
     */
    @Override
    protected SSLEngine engineCreateSSLEngine(String host, int port)
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineCreateSSLEngine(String host, int port)");

        if (this.ctx == null || this.authStore == null) {
            throw new IllegalStateException("SSLContext must be initialized " +
                "before use, please call init()");
        }

        try {
            return new WolfSSLEngine(this.ctx, this.authStore, this.params,
                host, port);
        } catch (WolfSSLException ex) {
            throw new IllegalStateException("Unable to create engine");
        }
    }

    /**
     * Returns the SSLServerSessionContext associated with this SSLContext.
     *
     * @throws UnsupportedOperationException operation not yet supported
     */
    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return authStore.getServerContext();
    }

    /**
     * Returns the SSLClientSessionContext associated with this SSLContext.
     *
     * @throws UnsupportedOperationException operation not yet supported
     */
    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return authStore.getClientContext();
    }

    /**
     * Returns copy of SSLParameters with default settings for this SSLContext.
     */
    @Override
    protected SSLParameters engineGetDefaultSSLParameters() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetDefaultSSLParameters()");

        return WolfSSLParametersHelper.decoupleParams(this.params);
    }

    /**
     * Returns copy of SSLParameters with max supported settings for this
     * SSLContext.
     */
    @Override
    protected SSLParameters engineGetSupportedSSLParameters() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetSupportedSSLParameters()");

        return WolfSSLParametersHelper.decoupleParams(this.params);
    }

    /**
     * Get WolfSSLAuthStore for this WolfSSLContext.
     * Used internally by SSLSocketFactory()
     *
     * @return WolfSSLAuthStore for this WolfSSLContext object
     */
    protected WolfSSLAuthStore getInternalAuthStore() {
        return this.authStore;
    }

    /**
     * Get internal SSLParameters.
     * Used internally by SSLSocketFactory()
     *
     * @return WolfSSLParameters for this WolfSSLContext object
     */
    protected WolfSSLParameters getInternalSSLParams() {
        return this.params;
    }

    /**
     * Get internal com.wolfssl.WolfSSLContext for this object.
     * Used internally by SSLSocketFactory()
     *
     * @return com.wolfssl.WolfSSLContext for this object
     */
    protected com.wolfssl.WolfSSLContext getInternalWolfSSLContext() {
        return this.ctx;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        if (this.ctx != null) {
            this.ctx = null;
        }
        super.finalize();
    }

    /**
     * Sets the WolfSSLContext options using specified protocol mask.
     * Also translates the protocol mask provided to an array of Strings
     * for the enabled SSL/TLS protocols.
     *
     * @param noOpt protocol mask set into native WOLFSSL_CTX
     *
     * @return String array of enabled SSL/TLS protocols for this
     *         WolfSSLContext object
     */
    public String[] getProtocolsMask(long noOpt) {
        if (ctx != null) {
            ctx.setOptions(noOpt);
        }
        return WolfSSL.getProtocolsMask(noOpt);
    }

    /**
     * SSLContext implementation supporting TLS 1.0
     */
    public static final class TLSV1_Context extends WolfSSLContext {
        /**
         * Create new TLSv1_Context, calls parent WolfSSLContext constructor
         */
        public TLSV1_Context() {
            super(TLS_VERSION.TLSv1);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using TLSV1_Context");
        }
    }

    /**
     * SSLContext implementation supporting TLS 1.1
     */
    public static final class TLSV11_Context extends WolfSSLContext {
        /**
         * Create new TLSv11_Context, calls parent WolfSSLContext constructor
         */
        public TLSV11_Context() {
            super(TLS_VERSION.TLSv1_1);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using TLSV11_Context");
        }
    }

    /**
     * SSLContext implementation supporting TLS 1.2
     */
    public static final class TLSV12_Context extends WolfSSLContext {
        /**
         * Create new TLSv12_Context, calls parent WolfSSLContext constructor
         */
        public TLSV12_Context() {
            super(TLS_VERSION.TLSv1_2);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using TLSV12_Context");
        }
    }

    /**
     * SSLContext implementation supporting TLS 1.3
     */
    public static final class TLSV13_Context extends WolfSSLContext {
        /**
         * Create new TLSv13_Context, calls parent WolfSSLContext constructor
         */
        public TLSV13_Context() {
            super(TLS_VERSION.TLSv1_3);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using TLSV13_Context");
        }
    }

    /**
     * TLSv23 SSLContext class.
     * Created using SSLv23 method, supporting highest protocol enabled
     * in native wolfSSL. Downgrades to native minimum downgrade level.
     */
    public static final class TLSV23_Context extends WolfSSLContext {
        /**
         * Create new TLSv23_Context, calls parent WolfSSLContext constructor
         */
        public TLSV23_Context() {
            super(TLS_VERSION.SSLv23);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using TLSV23_Context");
        }
    }


    /**
     * DEFAULT SSLContext class.
     * Created using SSLv23 method, supporting highest protocol enabled
     * in native wolfSSL. Downgrades to native minimum downgrade level.
     */
    public static final class DEFAULT_Context extends WolfSSLContext {
        /**
         * Create new DEFAULT_Context, calls parent WolfSSLContext constructor
         * with TLS_VERSION.SSLv23
         *
         * @throws IllegalStateException when engine init fails
         */
        public DEFAULT_Context() {
            super(TLS_VERSION.SSLv23);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating new WolfSSLContext using DEFAULT_Context");

            try {
                this.engineInit(null, null, null);
            } catch (Exception e) {
                throw new IllegalStateException("wolfSSL engine init failed");
            }
        }
    }
}

