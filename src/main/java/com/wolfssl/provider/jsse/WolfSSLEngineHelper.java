/* WolfSSLEngineHelper.java
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

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.SSLHandshakeException;
import java.security.Security;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * This is a helper class to account for similar methods between SSLSocket
 * and SSLEngine.
 *
 * This class wraps a new WOLFSSL object that is created (inside
 * WolfSSLSession). All methods are protected or private because this class
 * should only be used internally to wolfJSSE.
 *
 * @author wolfSSL
 */
public class WolfSSLEngineHelper {
    private volatile WolfSSLSession ssl = null;
    private WolfSSLImplementSSLSession session = null;
    private WolfSSLParameters params = null;

    /* Peer hostname, used for session cache lookup (combined with port),
     * and SNI as secondary if user has not set via SSLParameters */
    private String hostname = null;

    /* Peer port, used for session cache lookup (combined with hostname) */
    private int port;

    /* Peer InetAddress, may be set when creating SSLSocket, otherwise
     * will be null if String host constructor was used instead.
     * If hostname above is null, and user has not set SSLParameters,
     * if 'jdk.tls.trustNameService' property has been set will try to set
     * SNI based on this using peerAddr.getHostName() */
    private InetAddress peerAddr = null;

    /* Reference to WolfSSLAuthStore, comes from WolfSSLContext */
    private WolfSSLAuthStore authStore = null;

    /* Is this client side (true) or server (false) */
    private boolean clientMode;

    /* Is session creation allowed for this object */
    private boolean sessionCreation = true;

    /* Has setUseClientMode() been called on this object */
    private boolean modeSet = false;

    /* wolfSSL verification mode, set inside setLocalAuth() */
    private int verifyMask = WolfSSL.SSL_VERIFY_PEER;

    /* Internal Java verify callback, used when user/app is not using
     * com.wolfssl.provider.jsse.WolfSSLTrustX509 and instead using their
     * own TrustManager to perform verification via checkClientTrusted()
     * and/or checkServerTrusted().
     *
     * This object is stored at the native level as a global reference
     * created in Java_com_wolfssl_WolfSSLSession_setVerify()
     * of com_wolfssl_WolfSSLSession.c and deleted in native
     * Java_com_wolfssl_WolfSSLSession_freeSSL(). Deleting the native
     * global reference allows the Java object to be garbage collected. */
    private WolfSSLInternalVerifyCb wicb = null;

    /**
     * Always creates a new session
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @throws WolfSSLException if an exception happens during session creation
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            WolfSSLParameters params) throws WolfSSLException {

        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.authStore = store;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLEngineHelper()");
    }

    /**
     * Allows for new session and resume session by default
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @param port port number as hint for resume
     * @param hostname hostname as hint for resume and for default SNI
     * @throws WolfSSLException if an exception happens during session resume
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            WolfSSLParameters params, int port, String hostname)
            throws WolfSSLException {

        if (params == null || ssl == null || store == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.port = port;
        this.hostname = hostname;
        this.authStore = store;
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLEngineHelper(peer port: " + port +
            ", peer hostname: " + hostname + ")");
    }

    /**
     * Allows for new session and resume session by default
     * @param ssl WOLFSSL session
     * @param store main auth store holding session tables and managers
     * @param params default parameters to use on connection
     * @param port port number as hint for resume
     * @param peerAddr InetAddress of peer, used for session resumption and
     *                 SNI if system property is set
     * @throws WolfSSLException if an exception happens during session resume
     */
    protected WolfSSLEngineHelper(WolfSSLSession ssl, WolfSSLAuthStore store,
            WolfSSLParameters params, int port, InetAddress peerAddr)
            throws WolfSSLException {

        if (params == null || ssl == null || store == null ||
            peerAddr == null) {
            throw new WolfSSLException("Bad argument");
        }

        this.ssl = ssl;
        this.params = params;
        this.port = port;
        this.peerAddr = peerAddr;
        this.authStore = store;
        this.session = new WolfSSLImplementSSLSession(store);
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLEngineHelper(peer port: " + port +
            ", peer IP: " + peerAddr.getHostAddress() + ")");
    }

    /**
     * Get the alias from the X509KeyManager to use for finding and loading
     * the private key and certificate chain for this endpoint.
     *
     * @param km X509KeyManager or X509ExtendedKeyManager to poll for
     *        client/server alias name
     * @param socket Socket or SSLSocket from which this peer is being
     *        created, may be null if engine is being used instead
     * @param engine SSLEngine from which this peer is being created, may be
     *        null if socket is being used instead
     *
     * @return alias String, or null if none found
     */
    private String GetKeyAndCertChainAlias(X509KeyManager km, Socket sock,
        SSLEngine engine) {

        String alias = null;
        String javaVersion = System.getProperty("java.version");

        if (sock == null && engine == null) {
            return null;
        }

        /* If javaVersion is null, set to empty string */
        if (javaVersion == null) {
            javaVersion = "";
        }

        /* We only load keys from algorithms enabled in native wolfSSL,
         * and in the priority order of ECC first, then RSA. JDK 1.7.0_201
         * and 1.7.0_171 have a bug that causes PrivateKey.getEncoded() to
         * fail for EC keys. This has been fixed in later JDK versions,
         * but skip adding EC here if we're running on those versions . */
        ArrayList<String> keyAlgos = new ArrayList<String>();
        if (WolfSSL.EccEnabled() &&
            (!javaVersion.equals("1.7.0_201") &&
             !javaVersion.equals("1.7.0_171"))) {
            keyAlgos.add("EC");
        }
        if (WolfSSL.RsaEnabled()) {
            keyAlgos.add("RSA");
        }

        String[] keyTypes = new String[keyAlgos.size()];
        keyTypes = keyAlgos.toArray(keyTypes);

        if (clientMode) {
            if (sock != null) {
                alias = km.chooseClientAlias(keyTypes, null, sock);
            }
            else if (engine != null) {
                if (km instanceof X509ExtendedKeyManager) {
                    alias = ((X509ExtendedKeyManager)km).
                        chooseEngineClientAlias(keyTypes, null, engine);
                }
                else {
                    alias = km.chooseClientAlias(keyTypes, null, null);
                }
            }
        }
        else {
            /* Loop through available key types until we find an alias
             * that works, or none that do and return null */
            for (String type : keyTypes) {
                if (sock != null) {
                    alias = km.chooseServerAlias(type, null, sock);
                }
                else if (engine != null) {
                    if (km instanceof X509ExtendedKeyManager) {
                        alias = ((X509ExtendedKeyManager)km).
                            chooseEngineServerAlias(type, null, engine);
                    }
                    else {
                        alias = km.chooseServerAlias(type, null, null);
                    }
                }

                if (alias != null) {
                    break;
                }
            }
        }

        return alias;
    }

    /**
     * Loads the private key and certificate chain for this
     * SSLSocket/SSLEngine to be used for performing authentication of
     * this peer during the handshake.
     *
     * If there is no X509KeyManager in our WolfSSLAuthStore, skips loading
     * private key and certificate. This means SSLContext.init() was
     * initialized with a null KeyManager.
     *
     * @param sock Socket or SSLSocket associated with this connection, may
     *        be null if engine is used instead
     * @param engine SSLEngine associated with this connection, may be null
     *        if sock used instead
     *
     * @throws WolfSSLException if private key is not correct format,
     *         WolfSSLAuthStore is null, or native error when loading
     *         private key or certificate.
     * @throws CertificateEncodingException on error getting Certificate
     *         encoding before loading into native WOLFSSL
     * @throws IOException on error concatenating certificate chain into
     *         single byte array
     */
    protected synchronized void LoadKeyAndCertChain(
        Socket sock, SSLEngine engine)
        throws WolfSSLException, CertificateEncodingException, IOException {

        int ret;
        int offset;
        String alias = null;       /* KeyStore alias holding private key */
        X509KeyManager km = null;  /* X509KeyManager from KeyStore */

        if (this.authStore == null) {
            throw new WolfSSLException("WolfSSLAuthStore is null");
        }

        km = this.authStore.getX509KeyManager();
        if (km == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    "internal KeyManager is null, no cert/key to load");
            return;
        }

        /* Ask X509KeyManager to choose correct client alias from which
         * to load private key / cert chain */
        alias = GetKeyAndCertChainAlias(km, sock, engine);
        authStore.setCertAlias(alias);

        /* Load private key into WOLFSSL session */
        PrivateKey privKey = km.getPrivateKey(alias);

        if (privKey != null) {
            byte[] privKeyEncoded = privKey.getEncoded();
            if (!privKey.getFormat().equals("PKCS#8")) {
                throw new WolfSSLException(
                    "Private key is not in PKCS#8 format");
            }

            /* Skip past PKCS#8 offset */
            offset = WolfSSL.getPkcs8TraditionalOffset(privKeyEncoded, 0,
                privKeyEncoded.length);

            byte[] privKeyTraditional = Arrays.copyOfRange(privKeyEncoded,
                offset, privKeyEncoded.length);

            try {
                ret = this.ssl.usePrivateKeyBuffer(privKeyTraditional,
                    privKeyTraditional.length, WolfSSL.SSL_FILETYPE_ASN1);
            } catch (WolfSSLJNIException e) {
                throw new WolfSSLException(e);
            }

            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException("Failed to load private key " +
                    "buffer into WOLFSSL, err = " + ret);
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "loaded private key from X509KeyManager " +
                    "(alias: " + alias + ")");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "no private key found in X509KeyManager " +
                    "(alias: " + alias + "), skipped loading");
        }

        /* Load certificate chain */
        X509Certificate[] cert = km.getCertificateChain(alias);

        if (cert != null) {
            ByteArrayOutputStream certStream = new ByteArrayOutputStream();
            int chainLength = 0;
            for (int i = 0; i < cert.length; i++) {
                /* concatenate certs into single byte array */
                certStream.write(cert[i].getEncoded());
                chainLength++;
            }
            byte[] certChain = certStream.toByteArray();
            certStream.close();

            try {
                ret = this.ssl.useCertificateChainBufferFormat(certChain,
                    certChain.length, WolfSSL.SSL_FILETYPE_ASN1);
            } catch (WolfSSLJNIException e) {
                throw new WolfSSLException(e);
            }

            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new WolfSSLException("Failed to load certificate " +
                    "chain buffer into WOLFSSL, err = " + ret);
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "loaded certificate chain from KeyManager (alias: " +
                    alias + ", length: " +
                    chainLength + ")");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "no certificate or chain found " +
                    "(alias: " + alias + "), skipped loading");
        }
    }

    /**
     * Set hostname and port
     * Used internally by SSLSocket.connect(SocketAddress)
     *
     * @param hostname peer hostname String
     * @param port peer port number
     */
    protected synchronized void setHostAndPort(String hostname, int port) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setHostAndPort()");

        this.hostname = hostname;
        this.port = port;
    }

    /**
     * Set peer InetAddress.
     * Used by SSLSocket.connect() when InetAddress is passed in from user.
     *
     * @param peerAddr InetAddress of peer
     */
    protected synchronized void setPeerAddress(InetAddress peerAddr) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setPeerAddress()");

        this.peerAddr = peerAddr;
    }

    /**
     * Get the com.wolfssl.WolfSSLSession for this object
     *
     * @return com.wolfssl.WolfSSLSession for this object
     */
    protected synchronized WolfSSLSession getWolfSSLSession() {
        return ssl;
    }

    /**
     * Get WolfSSLImplementSession for this object
     *
     * @return WolfSSLImplementSession for this object
     */
    protected synchronized WolfSSLImplementSSLSession getSession() {

        if (this.session == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "this.session is null, creating new " +
                "WolfSSLImplementSSLSession");

            this.session = new WolfSSLImplementSSLSession(authStore);
        }
        return this.session;
    }

    /**
     * Get all supported cipher suites in native wolfSSL library, which
     * are also allowed by "wolfjsse.enabledCipherSuites" system Security
     * property, if set.
     *
     * @return String array of all supported cipher suites
     */
    protected synchronized String[] getAllCiphers() {
        return WolfSSLUtil.sanitizeSuites(WolfSSL.getCiphersIana());
    }

    /**
     * Get all enabled cipher suites, and allowed via
     * wolfjsse.enabledCipherSuites system Security property (if set).
     *
     * @return String array of all enabled cipher suites
     */
    protected synchronized String[] getCiphers() {
        return WolfSSLUtil.sanitizeSuites(this.params.getCipherSuites());
    }

    /**
     * Set cipher suites enabled in WolfSSLParameters
     *
     * Sanitizes input array for invalid suites
     *
     * @param suites String array of cipher suites to be enabled
     *
     * @throws IllegalArgumentException if input array contains invalid
     *         cipher suites, input array is null, or input array has length
     *         zero
     */
    protected synchronized void setCiphers(String[] suites)
        throws IllegalArgumentException {

        if (suites == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (suites.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize cipher array for unsupported strings */
        List<String> supported = Arrays.asList(getAllCiphers());
        for (int i = 0; i < suites.length; i++) {
            if (!supported.contains(suites[i])) {
                throw new IllegalArgumentException("Unsupported CipherSuite: " +
                    suites[i]);
            }
        }

        this.params.setCipherSuites(WolfSSLUtil.sanitizeSuites(suites));
    }

    /**
     * Set protocols enabled in WolfSSLParameters
     *
     * Sanitizes protocol array for invalid protocols
     *
     * @param p String array of SSL/TLS protocols to be enabled
     *
     * @throws IllegalArgumentException if input array is null,
     *         has length zero, or contains invalid/unsupported protocols
     */
    protected synchronized void setProtocols(String[] p)
        throws IllegalArgumentException {

        if (p == null) {
            throw new IllegalArgumentException("input array is null");
        }

        if (p.length == 0) {
            throw new IllegalArgumentException("input array has length zero");
        }

        /* sanitize protocol array for unsupported strings */
        List<String> supported = Arrays.asList(getAllProtocols());
        for (int i = 0; i < p.length; i++) {
            if (!supported.contains(p[i])) {
                throw new IllegalArgumentException("Unsupported protocol: " +
                    p[i]);
            }
        }

        this.params.setProtocols(WolfSSLUtil.sanitizeProtocols(p));
    }

    /**
     * Get enabled SSL/TLS protocols from WolfSSLParameters
     *
     * @return String array of enabled SSL/TLS protocols
     */
    protected synchronized String[] getProtocols() {
        return WolfSSLUtil.sanitizeProtocols(this.params.getProtocols());
    }

    /**
     * Get all supported SSL/TLS protocols in native wolfSSL library,
     * which are also allowed by 'jdk.tls.client.protocols' or
     * 'jdk.tls.server.protocols' if set.
     *
     * @return String array of supported protocols
     */
    protected synchronized String[] getAllProtocols() {
        return WolfSSLUtil.sanitizeProtocols(WolfSSL.getProtocols());
    }

    /**
     * Set client mode for associated WOLFSSL session
     *
     * @param mode client mode (true/false)
     *
     * @throws IllegalArgumentException if called after SSL/TLS handshake
     *         has been completed. Only allowed before.
     */
    protected synchronized void setUseClientMode(boolean mode)
        throws IllegalArgumentException {

        if (this.ssl.handshakeDone()) {
            throw new IllegalArgumentException("setUseClientMode() not " +
                "allowed after handshake is completed");
        }

        this.clientMode = mode;
        if (this.clientMode) {
            this.ssl.setConnectState();
        }
        else {
            this.ssl.setAcceptState();
        }
        this.modeSet = true;
    }

    /**
     * Get clientMode for associated session
     *
     * @return boolean value of clientMode set for this session
     */
    protected synchronized boolean getUseClientMode() {
        return this.clientMode;
    }

    /**
     * Set if session needs client authentication
     *
     * @param need boolean if session needs client authentication
     */
    protected synchronized void setNeedClientAuth(boolean need) {
        this.params.setNeedClientAuth(need);
    }

    /**
     * Get value of needClientAuth for this session
     *
     * @return boolean value for needClientAuth
     */
    protected synchronized boolean getNeedClientAuth() {
        return this.params.getNeedClientAuth();
    }

    /**
     * Set value of wantClientAuth for this session
     *
     * @param want boolean value of wantClientAuth for this session
     */
    protected synchronized void setWantClientAuth(boolean want) {
        this.params.setWantClientAuth(want);
    }

    /**
     * Get value of wantClientAuth for this session
     *
     * @return boolean value for wantClientAuth
     */
    protected synchronized boolean getWantClientAuth() {
        return this.params.getWantClientAuth();
    }

    /**
     * Set ability to create sessions
     *
     * @param flag boolean to set enable session creation
     */
    protected synchronized void setEnableSessionCreation(boolean flag) {
        this.sessionCreation = flag;
    }

    /**
     * Get boolean if session creation is allowed
     *
     * @return boolean value for enableSessionCreation
     */
    protected synchronized boolean getEnableSessionCreation() {
        return this.sessionCreation;
    }

    /**
     * Enable use of session tickets
     *
     * @param flag boolean to enable/disable session tickets
     */
    protected synchronized void setUseSessionTickets(boolean flag) {
        this.params.setUseSessionTickets(flag);
    }

    /**
     * Set ALPN protocols
     *
     * @param alpnProtos encoded byte array of ALPN protocols
     */
    protected synchronized void setAlpnProtocols(byte[] alpnProtos) {
        this.params.setAlpnProtocols(alpnProtos);
    }

    /**
     * Get selected ALPN protocol
     *
     * Used by some versions of Android, non-standard ALPN API.
     *
     * @return encoded byte array for selected ALPN protocol or null if
     *         handshake has not finished
     */
    protected synchronized byte[] getAlpnSelectedProtocol() {
        if (this.ssl.handshakeDone()) {
            return ssl.getAlpnSelected();
        }
        return null;
    }

    /**
     * Get selected ALPN protocol string
     *
     * @return String representation of selected ALPN protocol, null
     *         if protocol is not available yet, or empty String if
     *         ALPN will not be used for this connection.
     */
    protected synchronized String getAlpnSelectedProtocolString() {
        String proto = ssl.getAlpnSelectedString();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "selected ALPN protocol = " + proto);

        if (proto == null && this.ssl.handshakeDone()) {
            /* ALPN not used if proto is null and handshake is done */
            return "";
        }

        return proto;
    }

    /********** Calls to transfer over parameter to wolfSSL before connection */

    /*transfer over cipher suites right before establishing a connection */
    private void setLocalCiphers(String[] suites)
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
                if (this.ssl.setCipherList(list) != WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "error setting cipher list " + list);
                }
            }

        } catch (IllegalStateException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /* sets the protocol to use with WOLFSSL connections */
    private void setLocalProtocol(String[] p)
        throws SSLException {

        int i;
        long mask = 0;
        boolean[] set = new boolean[5];
        Arrays.fill(set, false);

        if (p == null) {
            /* if null then just use wolfSSL default */
            return;
        }

        if (p.length == 0) {
            throw new SSLException("No protocols enabled or available");
        }

        for (i = 0; i < p.length; i++) {
            if (p[i].equals("TLSv1.3")) {
                set[0] = true;
            }
            if (p[i].equals("TLSv1.2")) {
                set[1] = true;
            }
            if (p[i].equals("TLSv1.1")) {
                set[2] = true;
            }
            if (p[i].equals("TLSv1")) {
                set[3] = true;
            }
            if (p[i].equals("SSLv3")) {
                set[4] = true;
            }
        }

        if (set[0] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_3;
        }
        if (set[1] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_2;
        }
        if (set[2] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1_1;
        }
        if (set[3] == false) {
            mask |= WolfSSL.SSL_OP_NO_TLSv1;
        }
        if (set[4] == false) {
            mask |= WolfSSL.SSL_OP_NO_SSLv3;
        }
        this.ssl.setOptions(mask);
    }

    /* sets client auth on or off if needed / wanted */
    private void setLocalAuth(SSLSocket socket, SSLEngine engine) {
        int mask = WolfSSL.SSL_VERIFY_NONE;

        /* default to client side authenticating the server connecting to */
        if (this.clientMode) {
            mask = WolfSSL.SSL_VERIFY_PEER;
        }

        if (this.params.getWantClientAuth()) {
            mask |= WolfSSL.SSL_VERIFY_PEER;
        }
        if (this.params.getNeedClientAuth()) {
            mask |= (WolfSSL.SSL_VERIFY_PEER |
                    WolfSSL.SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
        }

        X509TrustManager tm = authStore.getX509TrustManager();
        wicb = new WolfSSLInternalVerifyCb(authStore.getX509TrustManager(),
                                           this.clientMode, socket, engine,
                                           this.params);

        if (tm instanceof com.wolfssl.provider.jsse.WolfSSLTrustX509) {
            /* use internal peer verification logic */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager is of type WolfSSLTrustX509");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Using native internal peer verification logic");

            /* Register Java verify callback for additional hostname
             * verification when SSLParameters Endpoint Identification
             * Algorithm has been set. To get this callback to be called,
             * native wolfSSL should be compiled with the following define:
             * WOLFSSL_ALWAYS_VERIFY_CB */
            this.verifyMask = mask;

        } else {
            /* not our own TrustManager, set up callback so JSSE can use
             * TrustManager.checkClientTrusted/checkServerTrusted() */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager is not of type WolfSSLTrustX509");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Using checkClientTrusted/ServerTrusted() for verification");
            this.verifyMask = WolfSSL.SSL_VERIFY_PEER;
        }

        this.ssl.setVerify(this.verifyMask, wicb);
    }


    /**
     * Get the value of a boolean system property.
     * If not set (property is null), use the default value given.
     *
     * @param prop System property to check
     * @param defaultVal Default value to use if property is null
     * @return Boolean value of the property, true/false
     */
    private static boolean checkBooleanProperty(String prop,
        boolean defaultVal) {

        String enabled = System.getProperty(prop);

        if (enabled == null) {
            return defaultVal;
        }

        if (enabled.equalsIgnoreCase("true")) {
            return true;
        }

        return false;
    }

    /**
     * Set SNI server names on client side.
     *
     * SNI names are only set if the 'jsse.enableSNIExtension' system
     * property has not been set to false. Default for this property
     * is defined by Oracle to be true.
     *
     * We first try to set SNI names from SSLParameters if set by the user.
     * If not set in SSLParameters, try to set using InetAddress.getHostName()
     * IFF 'jdk.tls.trustNameService` System property has been set to true.
     * Otherwise fall back and set based on hostname String if not null.
     * hostname String may be either IP address or fully qualified domain
     * name depending on what createSocket() API the user has called and with
     * what String.
     */
    private void setLocalServerNames() {

        /* Do not add SNI if system property has been set to false */
        boolean enableSNI =
            checkBooleanProperty("jsse.enableSNIExtension", true);

        /* Have we been instructed to trust the system name service for
         * reverse DNS lookups? */
        boolean trustNameService =
            checkBooleanProperty("jdk.tls.trustNameService", false);

        if (!enableSNI) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "jsse.enableSNIExtension property set to false, " +
                "not adding SNI to ClientHello");
        }
        else if (this.clientMode) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "jsse.enableSNIExtension property set to true, " +
                "enabling SNI");

            /* Explicitly set if user has set through SSLParameters */
            List<WolfSSLSNIServerName> names = this.params.getServerNames();
            if (names != null && names.size() > 0) {
                /* Should only be one server name */
                WolfSSLSNIServerName sni = names.get(0);
                if (sni != null) {
                    this.ssl.useSNI((byte)sni.getType(), sni.getEncoded());
                }

            } else {
                if (this.peerAddr != null && trustNameService) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "setting SNI extension with " +
                        "InetAddress.getHostName(): " +
                        this.peerAddr.getHostName());

                    this.ssl.useSNI((byte)0,
                        this.peerAddr.getHostName().getBytes());
                }
                else if (this.hostname != null) {
                    if (peerAddr != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "jdk.tls.trustNameService not set to true, " +
                            "not doing reverse DNS lookup to set SNI");
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "setting SNI extension with hostname: " +
                            this.hostname);
                    }
                    else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "peerAddr is null, setting SNI extension with " +
                            "hostname: " + this.hostname);
                    }
                    this.ssl.useSNI((byte)0, this.hostname.getBytes());

                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "hostname and peerAddr are null, not setting SNI");
                }
            }
        }
    }

    /* Session tickets are enabled in different ways depending on the JDK
     * implementation we are running on. For Oracle/OpenJDK, the following
     * system properties enable session tickets and were added in JDK 13:
     *
     * -Djdk.tls.client.enableSessionTicketExtension=true
     * -Djdk.tls.server.enableSessionTicketExtension=true
     *
     *  wolfJSSE currently supports client-side session ticket support, but
     *  not yet enabling of server-side support.
     *
     *  On Android, some libraries/frameworks (ex: okhttp) expect to enable
     *  session tickets per SSLSocket by calling a custom SSLSocket extension
     *  method called SSLSocket.setUseSessionTickets().
     *
     *  Note that for session ticket support in wolfJSSE, underlying native
     *  wolfSSL must be compiled with session ticket support enabled. This
     *  is done via "--enable-session-ticket" or "-DHAVE_SESSION_TICKET".
     */
    private void setLocalSessionTicket() {
        if (this.clientMode) {

            boolean enableFlag = this.params.getUseSessionTickets();
            String enableProperty = System.getProperty(
                    "jdk.tls.client.enableSessionTicketExtension");

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "SSLSocket.setUseSessionTickets() set to: " +
                String.valueOf(enableFlag));

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "jdk.tls.client.enableSessionTicketExtension property: " +
                enableProperty);

            if ((enableFlag == true) ||
                ((enableProperty != null) &&
                 (enableProperty.equalsIgnoreCase("true")))) {

                /* enable client-side session ticket support */
                this.ssl.useSessionTicket();

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session tickets enabled for this session");

            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session tickets not enabled on this session");
            }
        }
    }

    /* Set the ALPN to be used for this session */
    private void setLocalAlpnProtocols() {

        /* ALPN protocol list could be stored in either of the following,
         * depending on what platform/JDK we are being used on:
         *     this.params.getAlpnProtos() or
         *     this.params.getApplicationProtocols()
         * For example, Conscrypt consumers on older Android versions with
         * JDK 7 will be in params.getAlpnProtos(). JDK versions > 8, with
         * support for params.getApplicationProtocols() will likely use that
         * instead. */

        int i;
        byte[] alpnProtos = this.params.getAlpnProtos();
        String[] applicationProtocols = this.params.getApplicationProtocols();

        if ((alpnProtos != null && alpnProtos.length > 0) &&
            (applicationProtocols != null && applicationProtocols.length > 0)) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ALPN protocols found in both params.getAlpnProtos() and " +
                "params.getApplicationProtocols()");
        }

        /* try to set from byte[] first, then overwrite with String[] if
         * both have been set */
        if (alpnProtos != null && alpnProtos.length > 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Setting ALPN protocols for WOLFSSL session from byte[" +
                alpnProtos.length + "]");
            this.ssl.useALPN(alpnProtos);
        }

        if (applicationProtocols != null && applicationProtocols.length > 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Setting Application Protocols for WOLFSSL session " +
                "from String[]:");
            for (i = 0; i < applicationProtocols.length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "\t" + i + ": " + applicationProtocols[i]);
            }

            /* fail on mismatch */
            this.ssl.useALPN(applicationProtocols,
                             WolfSSL.WOLFSSL_ALPN_FAILED_ON_MISMATCH);
        }

        if (alpnProtos == null && applicationProtocols == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "No ALPN protocols set, not setting for this WOLFSSL session");
        }
    }

    private void setLocalSecureRenegotiation() {
        /* Enable secure renegotiation if native wolfSSL has been compiled
         * with HAVE_SECURE_RENEGOTIATION. Some JSSE consuming apps
         * expect that secure renegotiation will be supported. */
        int ret = this.ssl.useSecureRenegotiation();
        if (ret != WolfSSL.SSL_SUCCESS && ret != WolfSSL.NOT_COMPILED_IN) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "error enabling secure renegotiation, ret = " + ret);
        } else if (ret == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "enabled secure renegotiation support for session");
        }
    }

    private void setLocalSigAlgorithms() {

        int ret = 0;

        if (this.clientMode) {
            /* Get restricted signature algorithms for ClientHello if set by
             * user in "wolfjsse.enabledSigAlgorithms" Security property */
            String sigAlgos = WolfSSLUtil.getSignatureAlgorithms();

            if (sigAlgos != null) {
                ret = this.ssl.setSignatureAlgorithms(sigAlgos);
                if (ret != WolfSSL.SSL_SUCCESS &&
                    ret != WolfSSL.NOT_COMPILED_IN) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "error restricting signature algorithms based on " +
                        "wolfjsse.enabledSignatureAlgorithms property");
                } else if (ret == WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "restricted signature algorithms based on " +
                        "wolfjsse.enabledSignatureAlgorithms property");
                }
            }
        }
    }

    private void setLocalSupportedCurves() throws SSLException {

        int ret = 0;

        if (this.clientMode) {
            /* Get restricted supported curves for ClientHello if set by
             * user in "wolfjsse.enabledSupportedCurves" Security property */
            String[] curves = WolfSSLUtil.getSupportedCurves();

            if (curves != null) {
                ret = this.ssl.useSupportedCurves(curves);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    if (ret == WolfSSL.NOT_COMPILED_IN) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "Unable to set requested TLS Supported Curves, " +
                            "native support not compiled in.");
                    }
                    else {
                        throw new SSLException(
                            "Error setting TLS Supported Curves based on " +
                            "wolfjsse.enabledSupportedCurves property, ret = " +
                            ret + ", curves: " + Arrays.toString(curves));
                    }
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "set TLS Supported Curves based on " +
                        "wolfjsse.enabledSupportedCurves property");
                }
            }
        }
    }

    private void setLocalParams(SSLSocket socket, SSLEngine engine)
        throws SSLException {

        this.setLocalCiphers(
            WolfSSLUtil.sanitizeSuites(this.params.getCipherSuites()));
        this.setLocalProtocol(
            WolfSSLUtil.sanitizeProtocols(this.params.getProtocols()));
        this.setLocalAuth(socket, engine);
        this.setLocalServerNames();
        this.setLocalSessionTicket();
        this.setLocalAlpnProtocols();
        this.setLocalSecureRenegotiation();
        this.setLocalSigAlgorithms();
        this.setLocalSupportedCurves();
    }

    /**
     * Sets all parameters from WolfSSLParameters into native WOLFSSL object
     * and creates session. Accepts reference to SSLSocket which is calling
     * this, to be used in ExtendedX509TrustManager hostname verification
     * during handshake.
     *
     * This should be called before doHandshake()
     *
     * @param socket SSLSocket from which this method is being called.
     *
     * @throws SSLException if setUseClientMode() has not been called or
     *                      on native socket error
     * @throws SSLHandshakeException session creation is not allowed
     *
     */
    protected synchronized void initHandshake(SSLSocket socket)
        throws SSLException {

        initHandshakeInternal(socket, null);
    }

    /**
     * Sets all parameters from WolfSSLParameters into native WOLFSSL object
     * and creates session. Accepts reference to SSLEngine which is calling
     * this, to be used in ExtendedX509TrustManager hostname verification
     * during handshake.
     *
     * This should be called before doHandshake()
     *
     * @param engine SSLEngine from which this method is being called.
     *
     * @throws SSLException if setUseClientMode() has not been called or
     *                      on native socket error
     * @throws SSLHandshakeException session creation is not allowed
     *
     */
    protected synchronized void initHandshake(SSLEngine engine)
        throws SSLException {

        initHandshakeInternal(null, engine);
    }

    /**
     * Private internal method called by initHandshake() variants which
     * accept either SSLSocket or SSLEngine.
     *
     * Only one or the other between SSLSocket or SSLEngien should be provided
     * at one time, not both. The other should be set to null.
     *
     * @param socket SSLSocket from which this method is being called.
     * @param engine SSLEngine from which this method is being called.
     * @throws SSLHandshakeException session creation is not allowed
     *
     */
    private void initHandshakeInternal(SSLSocket socket, SSLEngine engine)
        throws SSLException {

        String sessCacheHostname = this.hostname;

        if (!modeSet) {
            throw new SSLException("setUseClientMode has not been called");
        }

        /* If InetAddress was used to create SSLSocket, use IP address for
         * session resumption to avoid DNS lookup with
         * InetAddress.getHostName(). Can cause performance issues if DNS server
         * is not available and timeout is long. */
        if (sessCacheHostname == null && this.peerAddr != null) {
            sessCacheHostname = this.peerAddr.getHostAddress();
        }

        /* create non null session */
        this.session = this.authStore.getSession(ssl, this.port,
            sessCacheHostname, this.clientMode, getCiphers(), getProtocols());

        if (this.session != null) {
            if (this.clientMode) {
                this.session.setSessionContext(authStore.getClientContext());
                this.session.setSide(WolfSSL.WOLFSSL_CLIENT_END);
            }
            else {
                this.session.setSessionContext(authStore.getServerContext());
                this.session.setSide(WolfSSL.WOLFSSL_SERVER_END);
            }

            if (this.sessionCreation == false && !this.session.isFromTable) {
                /* new handshakes can not be made in this case. */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "session creation not allowed");

                /* send CloseNotify */
                /* TODO: SunJSSE sends a Handshake Failure alert instead here */
                try {
                    this.ssl.shutdownSSL();
                } catch (SocketException | SocketTimeoutException e) {
                    throw new SSLException(e);
                }

                throw new SSLHandshakeException("Session creation not allowed");
            }
        }

        this.setLocalParams(socket, engine);
    }

    /**
     * Start or continue handshake
     *
     * Callers should not loop on WANT_READ/WRITE when used with SSLEngine.
     *
     * @param isSSLEngine specifies if this is being called by an SSLEngine
     *                    or not.
     * @param timeout socket timeout (milliseconds) for connect(), or 0 for
     *                infinite/no timeout.
     * @return WolfSSL.SSL_SUCCESS on success or either WolfSSL.SSL_FAILURE
     *         or WolfSSL.SSL_HANDSHAKE_FAILURE on error
     *
     * @throws SSLException if setUseClientMode() has not been called or
     *                      on native socket error
     * @throws SocketTimeoutException if socket timed out
     */
    protected synchronized int doHandshake(int isSSLEngine, int timeout)
        throws SSLException, SocketTimeoutException {

        int ret, err;
        byte[] serverId = null;
        String hostAddress = null;

        if (!modeSet) {
            throw new SSLException("setUseClientMode has not been called");
        }

        if (this.sessionCreation == false && !this.session.isFromTable) {
            /* new handshakes can not be made in this case. */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session creation not allowed");

            try {
                /* send CloseNotify */
                /* TODO: SunJSSE sends a Handshake Failure alert instead here */
                this.ssl.shutdownSSL();
            } catch (SocketException e) {
                throw new SSLException(e);
            }

            return WolfSSL.SSL_HANDSHAKE_FAILURE;
        }

        if ((this.session == null) || !this.session.isValid()) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session is marked as invalid, try creating a new session");
            if (this.sessionCreation == false) {
                /* new handshakes can not be made in this case. */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "session creation not allowed");

                return WolfSSL.SSL_HANDSHAKE_FAILURE;
            }
            this.session = this.authStore.getSession(ssl, this.clientMode);
        }

        if (this.clientMode) {
            /* Associate host:port as serverID for client session cache,
             * helps native wolfSSL for TLS 1.3 sessions with no session ID.
             * If host is null and Socket was created with InetAddress only,
             * try to use IP address:port instead. If both are null, skip
             * setting serverID. Setting newSession to 1 for setServerID since
             * we are controlling get/set session from Java */
            if (hostname != null) {
                serverId = this.hostname.concat(
                    Integer.toString(this.port)).getBytes();
            }
            else if (peerAddr != null) {
                hostAddress = this.peerAddr.getHostAddress();
                if (hostAddress != null) {
                    serverId = hostAddress.concat(
                        Integer.toString(this.port)).getBytes();
                }
            }
            if (serverId == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "null serverId when trying to generate, not setting");
            } else {
                ret = this.ssl.setServerID(serverId, 1);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    return WolfSSL.SSL_HANDSHAKE_FAILURE;
                }
            }
        }

        do {
            /* call connect() or accept() to do handshake, looping on
             * WANT_READ/WANT_WRITE errors in case underlying Socket is
             * non-blocking */
            try {
                if (this.clientMode) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "calling native wolfSSL_connect()");
                    /* may throw SocketTimeoutException on socket timeout */
                    ret = this.ssl.connect(timeout);

                } else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "calling native wolfSSL_accept()");
                    ret = this.ssl.accept(timeout);
                }
                err = ssl.getError(ret);

            } catch (SocketException e) {
                /* SocketException may be thrown if native socket
                 * select/poll() fails. Propogate errno back inside new
                 * SSLException. */
                throw new SSLException(e);
            }

        } while (ret != WolfSSL.SSL_SUCCESS && isSSLEngine == 0 &&
                 (err == WolfSSL.SSL_ERROR_WANT_READ ||
                  err == WolfSSL.SSL_ERROR_WANT_WRITE));

        /* Update cached values in WolfSSLImplementSSLSession from
         * WolfSSLSession, in case that goes out of scope and is garbage
         * collected (ex: protocol version). */
        this.session.updateStoredSessionValues();

        return ret;
    }

    /**
     * Unset the native verify callback and reset internal verify
     * callback state.
     *
     * This helper method is called by SSLEngine to reset the native
     * wolfSSL verify callback back to null. Since a pointer to that verify
     * callback is stored as a global JNI variable, it can prevent garbage
     * collection from being done. This helper can be called when an SSLEngine
     * or SSLSocket is closed/done to reset the verify callback.
     *
     * The verify callback will be set again if needed when
     * initHandshake() is called.
     */
    protected synchronized void unsetVerifyCallback() {
        /* Set native callback to null, releases JNI global and allows for
         * garbage collection if needed */
        if (this.ssl != null) {
            this.ssl.setVerify(this.verifyMask, null);
        }

        /* Reset internal state of WolfSSLInternalVerifyCallback, removes
         * references to SSLSocket/SSLEngine to allow garbage collection if
         * needed */
        if (this.wicb != null) {
            this.wicb.clearInternalVars();
            this.wicb = null;
        }
    }

    /**
     * Saves session on connection close for resumption
     *
     * @return WolfSSL.SSL_SUCCESS if session was saved into cache, otherwise
     *         WolfSSL.SSL_FAILURE
     */
    protected synchronized int saveSession() {
        if (this.session != null && this.session.isValid()) {
            /* Update values from WOLFSSL which are stored in
             * WolfSSLImplementSSLSession (ex: protocol) */
            this.session.updateStoredSessionValues();

            if (this.clientMode) {
                /* Only need to set resume on client side, server-side
                 * maintains session cache at native level. */
                this.session.setResume();
            }
            return this.authStore.addSession(this.session);
        }

        return WolfSSL.SSL_FAILURE;
    }

    protected synchronized void clearObjectState() {
        this.ssl = null;
        this.session = null;
        this.params = null;
        this.authStore = null;
    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {

        /* Reset this.ssl to null, but don't explicitly free. This object
         * may be used by wrapper object to WolfSSLEngineHelper and should
         * be freed there */
        this.ssl = null;
        this.wicb = null;

        this.session = null;
        this.params = null;
        this.authStore = null;
        super.finalize();
    }
}

