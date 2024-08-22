/* WolfSSLCertManager.java
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

package com.wolfssl;

import java.util.Enumeration;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import com.wolfssl.WolfSSLException;

/**
 * CertManager class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 */
public class WolfSSLCertManager {
    private boolean active = false;
    private long cmPtr = 0;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native WOLFSSL_CERT_MANAGER pointer use */
    private final Object cmLock = new Object();

    static native long CertManagerNew();
    static native void CertManagerFree(long cm);
    static native int CertManagerLoadCA(long cm, String f, String d);
    static native int CertManagerLoadCABuffer(long cm, byte[] in, long sz,
                                              int format);
    static native int CertManagerUnloadCAs(long cm);
    static native int CertManagerVerifyBuffer(long cm, byte[] in, long sz,
                                              int format);

    /**
     * Create new WolfSSLCertManager object
     *
     * @throws WolfSSLException if unable to create new manager
     */
    public WolfSSLCertManager() throws WolfSSLException {
        cmPtr = CertManagerNew();
        if (cmPtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertManager");
        }
        this.active = true;
    }

    /**
     * Verifies that the current WolfSSLCertManager object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private synchronized void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLCertManager object has been freed");
            }
        }
    }

    /**
     * Load CA into CertManager
     *
     * @param f X.509 certificate file to load
     * @param d directory of X.509 certs to load, or null
     *
     * @return WolfSSL.SSL_SUCESS on success, negative on error
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public synchronized int CertManagerLoadCA(String f, String d)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (cmLock) {
            return CertManagerLoadCA(this.cmPtr, f, d);
        }
    }

    /**
     * Load CA into CertManager from byte array
     *
     * @param in byte array holding X.509 certificate to load
     * @param sz size of input byte array, bytes
     * @param format format of input certificate, either
     *               WolfSSL.SSL_FILETYPE_PEM (PEM formatted) or
     *               WolfSSL.SSL_FILETYPE_ASN1 (ASN.1/DER).
     *
     * @return WolfSSL.SSL_SUCCESS on success, negative on error
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public synchronized int CertManagerLoadCABuffer(
        byte[] in, long sz, int format) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (cmLock) {
            return CertManagerLoadCABuffer(this.cmPtr, in, sz, format);
        }
    }

    /**
     * Loads KeyStore certificates into WolfSSLCertManager object.
     *
     * @param  ks - input KeyStore from which to load CA certs
     * @return WolfSSL.SSL_SUCCESS if at least one cert was loaded
     *         successfully, otherwise WolfSSL.SSL_FAILURE.
     * @throws WolfSSLException on exception working with KeyStore
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public synchronized int CertManagerLoadCAKeyStore(KeyStore ks)
        throws WolfSSLException, IllegalStateException {

        int ret = 0;
        int loadedCerts = 0;

        confirmObjectIsActive();

        if (ks == null) {
            throw new WolfSSLException("Input KeyStore is null");
        }

        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate cert = null;

                if (ks.isKeyEntry(name)) {
                    Certificate[] chain = ks.getCertificateChain(name);
                    if (chain != null) {
                        cert = (X509Certificate) chain[0];
                    }
                } else {
                    cert = (X509Certificate) ks.getCertificate(name);
                }

                if (cert != null && cert.getBasicConstraints() >= 0) {
                    ret = CertManagerLoadCABuffer(cert.getEncoded(),
                            cert.getEncoded().length,
                            WolfSSL.SSL_FILETYPE_ASN1);

                    if (ret == WolfSSL.SSL_SUCCESS) {
                        loadedCerts++;
                    }
                }
            }
        } catch (KeyStoreException | CertificateEncodingException ex) {
            throw new WolfSSLException(ex);
        }

        if (loadedCerts > 0) {
            return WolfSSL.SSL_SUCCESS;
        } else {
            return WolfSSL.SSL_FAILURE;
        }
    }

    /**
     * Unload any CAs that have been loaded into WolfSSLCertManager object.
     *
     * @return WolfSSL.SSL_SUCCESS on success, negative on error.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public synchronized int CertManagerUnloadCAs()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (cmLock) {
            return CertManagerUnloadCAs(this.cmPtr);
        }
    }

    /**
     * Verify X.509 certificate held in byte array
     *
     * @param in input X.509 certificate as byte array
     * @param sz size of input certificate array, bytes
     * @param format format of input certificate, either
     *               WolfSSL.SSL_FILETYPE_PEM (PEM formatted) or
     *               WolfSSL.SSL_FILETYPE_ASN1 (ASN.1/DER).
     *
     * @return WolfSSL.SSL_SUCCESS on successful verification, otherwise
     *         negative on error.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public synchronized int CertManagerVerifyBuffer(
        byte[] in, long sz, int format) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (cmLock) {
            return CertManagerVerifyBuffer(this.cmPtr, in, sz, format);
        }
    }

    /**
     * Frees CertManager object
     * @see WolfSSLSession#freeSSL()
     */
    public synchronized void free() throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (cmLock) {
                /* free native resources */
                CertManagerFree(this.cmPtr);

                /* free Java resources */
                this.active = false;
                this.cmPtr = 0;
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        try {
            /* checks active state in this.free() */
            this.free();
        } catch (IllegalStateException e) {
            /* already freed */
        }
        super.finalize();
    }
}
