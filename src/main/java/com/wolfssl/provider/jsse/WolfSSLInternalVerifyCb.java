/* WolfSSLInternalVerifyCb.java
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

import com.wolfssl.WolfSSLVerifyCallback;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLX509StoreCtx;
import com.wolfssl.provider.jsse.WolfSSLInternalVerifyCb;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;

/**
 * Internal verify callback.
 * This is used when a user registers a TrustManager which is NOT
 * com.wolfssl.provider.jsse.WolfSSLTrustManager. It is used to call
 * TrustManager checkClientTrusted() or checkServerTrusted().
 * If wolfJSSE TrustManager is used, native wolfSSL does certificate
 * verification internally. Used by WolfSSLEngineHelper.
 */
public class WolfSSLInternalVerifyCb implements WolfSSLVerifyCallback {

    private X509TrustManager tm = null;
    private boolean clientMode;
    private SSLSocket callingSocket = null;
    private SSLEngine callingEngine = null;
    private WolfSSLParameters params = null;

    /**
     * Create new WolfSSLInternalVerifyCb
     *
     * @param xtm X509TrustManager to use with this object
     * @param client boolean representing if this is client side
     * @param socket SSLSocket associated with this callback, or null
     * @param engine SSLEngine associated with this callback, or null
     * @param params WolfSSLParameters associated with this callback
     */
    public WolfSSLInternalVerifyCb(X509TrustManager xtm, boolean client,
        SSLSocket socket, SSLEngine engine, WolfSSLParameters params) {
        this.tm = xtm;
        this.clientMode = client;
        this.callingSocket = socket;
        this.callingEngine = engine;
        this.params = params;
    }

    /**
     * Reset internal variables back to null/default.
     */
    protected void clearInternalVars() {
        this.callingSocket = null;
        this.callingEngine = null;
        this.params = null;
        this.tm = null;
    }

    /**
     * Verify hostname of provided peer certificate using
     * Endpoint Identification Algorithm if set in SSLParameters.
     *
     * Used by verifyCallback() only for case where internal native wolfSSL
     * peer verification is done. Otherwise, hostname is verified as part
     * of full cert validation later in verifyCallback().
     *
     * @param peer peer certificate to use for hostname verification
     *
     * @return 1 if hostname verification was successful (allows verify
     *         callback to proceed, otherwise 0 if verification was not
     *         successful (or not able to do it since Endpoitn Identification
     *         Algorithm has not been set).
     */
    private int verifyHostnameOnly(X509Certificate peer) {

        WolfSSLTrustX509 wolfTM = (WolfSSLTrustX509)tm;

        try {
            if (this.callingSocket != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "checking hostname verification using SSLSocket");
                /* Throws CertificateException when verify fails */
                wolfTM.verifyHostname(peer, this.callingSocket,
                    null, clientMode);
            }
            else if (this.callingEngine != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "checking hostname verification using SSLEngine");
                /* Throws CertificateException when verify fails */
                wolfTM.verifyHostname(peer, null,
                    this.callingEngine, clientMode);
            }
            else {
                throw new CertificateException(
                    "Both SSLSocket and SSLEngine null when trying to " +
                    "do hostname verification");
            }
        } catch (CertificateException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509ExtendedTrustManager hostname verification failed: " +
                e.getMessage());
            return 0;
        }

        /* Hostname verification successful */
        return 1;
    }

    /**
     * Calls registered X509TrustManager / X509ExtendedTrustManager to
     * verify certificate chain.
     *
     * @param certs Peer certificate chain to validate
     * @param authType Authentication type
     *
     * @return true on successful validation, otherwise false on failure
     */
    private boolean VerifyCertChainWithTrustManager(X509Certificate[] certs,
        String authType) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Verifying peer with X509TrustManager: " + this.tm);
        if (this.tm instanceof X509ExtendedTrustManager) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager of type X509ExtendedTrustManager");
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "X509TrustManager of type X509TrustManager");
        }

        try {
            /* Call TrustManager to do cert verification, should throw
             * CertificateException if verification fails */
            if (this.clientMode) {
                if (this.tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager xtm =
                        (X509ExtendedTrustManager)this.tm;
                    if (this.callingSocket != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          "Calling TrustManager.checkServerTrusted(SSLSocket)");
                        xtm.checkServerTrusted(certs, authType,
                            this.callingSocket);
                    }
                    else if (this.callingEngine != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          "Calling TrustManager.checkServerTrusted(SSLEngine)");
                        xtm.checkServerTrusted(certs, authType,
                            this.callingEngine);
                    }
                    else {
                        /* If we do have access to X509ExtendedTrustManager,
                         * but don't have SSLSocket/Engine, error out instead
                         * of falling back to verify without hostname. */
                        throw new Exception(
                            "SSLSocket/SSLEngine null during server peer " +
                            "verification, failed to verify");
                    }
                }
                else {
                    /* Basic X509TrustManager does not support HTTPS
                     * hostname verification, no SSLSocket/Engine needed */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Calling TrustManager.checkServerTrusted()");
                    this.tm.checkServerTrusted(certs, authType);
                }

            } else {
                if (this.tm instanceof X509ExtendedTrustManager) {
                    X509ExtendedTrustManager xtm =
                        (X509ExtendedTrustManager)this.tm;
                    if (this.callingSocket != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          "Calling TrustManager.checkClientTrusted(SSLSocket)");
                        xtm.checkClientTrusted(certs, authType,
                            this.callingSocket);
                    }
                    else if (this.callingEngine != null) {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                          "Calling TrustManager.checkClientTrusted(SSLEngine)");
                        xtm.checkClientTrusted(certs, authType,
                            this.callingEngine);
                    }
                    else {
                        /* If we do have access to X509ExtendedTrustManager,
                         * but don't have SSLSocket/Engine, error out instead
                         * of falling back to verify without hostname. */
                        throw new Exception(
                            "SSLSocket/SSLEngine null during client peer " +
                            "verification, failed to verify");
                    }
                }
                else {
                    /* Basic X509TrustManager does not support HTTPS
                     * hostname verification, no SSLSocket/Engine needed */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Calling TrustManager.checkClientTrusted()");
                    this.tm.checkClientTrusted(certs, authType);
                }
            }
        } catch (Exception e) {
            /* TrustManager rejected certificate, not valid */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "TrustManager rejected certificates, verification failed: " +
                e.getMessage());
            return false;
        }

        return true;
    }

    /**
     * Native wolfSSL verify callback.
     *
     * @param preverify_ok Will be 1 if native wolfSSL verification
     *        procedured have passed, otherwise 0.
     * @param x509StorePtr Native pointer to WOLFSSL_X509_STORE structure
     *
     * @return 1 if verification should be considered successful and
     *         SSL/TLS handshake should continue. Otherwise return 0
     *         to mark verification failure and stop/abort handshake.
     */
    public int verifyCallback(int preverify_ok, long x509StorePtr) {

        WolfSSLCertificate[] certs = null;
        String authType = null;
        X509Certificate[] x509certs = new X509Certificate[0];

        if (preverify_ok == 1) {
            /* When using WolfSSLTrustX509 implementation of
             * X509TrustManager, we use internal wolfSSL verification logic
             * but register this verify callback (always called) so that
             * we can do additional hostname verification if user has set
             * the Endpoint Identification Algorithm in SSLParameters.
             * Note that certificate verification has already been done and
             * passed if preverify_ok == 1, so we skip doing it again here
             * later on for this case */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Native wolfSSL peer verification passed (clientMode: " +
                    this.clientMode + ")");
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "NOTE: Native wolfSSL peer verification failed " +
                    "(clientMode: " + this.clientMode + ")");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "      Continuing with X509TrustManager verification");
        }

        try {
            /* get WolfSSLCertificate[] from x509StorePtr */
            WolfSSLX509StoreCtx store =
                new WolfSSLX509StoreCtx(x509StorePtr);
            certs = store.getCerts();

        } catch (WolfSSLException e) {
            /* failed to get certs from native, give app null array */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Failed to get certs from x509StorePtr, certs = null: " +
                e.getMessage());
            certs = null;
        }

        if (certs != null && certs.length > 0) {
            try {
                /* Convert WolfSSLCertificate[] to X509Certificate[] */
                x509certs = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    x509certs[i] = certs[i].getX509Certificate();
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Peer cert: " + x509certs[i].getSubjectDN().getName());
                }
            } catch (CertificateException | IOException |
                     WolfSSLJNIException ce) {
                /* failed to get cert array, give app empty array */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Failed to get X509Certificate[] array, set to " +
                    "empty array: " + ce.getMessage());
                x509certs = new X509Certificate[0];
            }

            /* get authType, use first cert */
            String sigType = certs[0].getSignatureType();
            if (sigType.contains("RSA")) {
                authType = "RSA";
            } else if (sigType.contains("ECDSA")) {
                authType = "ECDSA";
            } else if (sigType.contains("DSA")) {
                authType = "DSA";
            } else if (sigType.contains("ED25519")) {
                authType = "ED25519";
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Auth type: " + authType);

            /* Free native WolfSSLCertificate memory. At this
             * point x509certs[] is all Java managed memory now. */
            for (int i = 0; i < certs.length; i++) {
                certs[i].free();
            }
        }

        /* Case where native wolfSSL verification was already done and passed
         * and we only want to do hostname verification if needed additionally.
         * We do that here and return before going on to additional
         * checkServerTrusted/checkClientTrusted() so that we do not
         * duplicate verification. */
        if ((preverify_ok == 1) && (x509certs.length > 0) &&
            (tm instanceof WolfSSLTrustX509)) {
            return verifyHostnameOnly(x509certs[0]);
        }

        /* If server-side application has explicitly disabled client
         * authentication, return as success and skip X509TrustManager
         * verification */
        if ((!this.clientMode) && (this.params != null) &&
            (!this.params.getNeedClientAuth())) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Application has disabled client verification with " +
                "setNeedClientAuth(false), skipping verification");
            return 1;
        }
        else if ((preverify_ok == 1) && (x509certs.length == 0) &&
            (!this.clientMode) && (this.params != null) &&
            this.params.getWantClientAuth() &&
            (!this.params.getNeedClientAuth())) {
            /* If native wolfSSL verification has passed, and we have no peer
             * certificates, if application has set client authentication be
             * requested (wantClientAuth == true), but not fatal if no
             * certificate was sent (needClientAuth == false), don't call
             * TrustManager with empty certificate chain just consider
             * verification successful at this point */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "No client cert sent and client auth marked optional, not " +
                "calling TrustManager for hostname verification");
        }
        else {
            /* Poll X509TrustManager / X509ExtendedTrustManager for certificate
             * verification status. Returns 0 if certificates are rejected,
             * otherwise 1 on successful verification */
            if (VerifyCertChainWithTrustManager(x509certs, authType) == false) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "TrustManager verification failed");
                /* Abort handshake, verification failed */
                return 0;
            }
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "TrustManager verification successful");

        /* Continue handshake, verification succeeded */
        return 1;
    }
}

