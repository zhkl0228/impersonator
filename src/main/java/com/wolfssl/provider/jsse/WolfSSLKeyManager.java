/* WolfSSLKeyManager.java
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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;

/**
 * WolfSSL KeyManagerFactory implementation
 */
public class WolfSSLKeyManager extends KeyManagerFactorySpi {
    private char[] pswd = null;
    private KeyStore store = null;
    private boolean initialized = false;

    /** Default WolfSSLKeyManager constructor */
    public WolfSSLKeyManager() { }

    /**
     * Try to load KeyStore from System properties if set.
     *
     * If a KeyStore file has been specified in the javax.net.ssl.keyStore
     * System property, then we try to load it in the following ways:
     *
     *   1. Using type specified in javax.net.ssl.keyStoreType. If not given:
     *   2. Using wolfJCE WKS type, if available
     *   3. Using BKS type if on Android
     *   4. Using JKS type if above all fail
     *
     * @param requiredType KeyStore type required by user through
     *        java.security if wolfjsse.keystore.type.required property
     *        has been set.
     *
     * @return new KeyStore object that has been created and loaded using
     *         details specified in System properties.
     *
     * @throws KeyStoreException if javax.net.ssl.keyStore property is
     *         set but KeyStore fails to load
     */
    private KeyStore LoadKeyStoreFromSystemProperties(String requiredType)
        throws KeyStoreException {

        KeyStore sysStore = null;
        InputStream stream = null;
        String pass = System.getProperty("javax.net.ssl.keyStorePassword");
        String file = System.getProperty("javax.net.ssl.keyStore");
        String type = System.getProperty("javax.net.ssl.keyStoreType");
        boolean wksAvailable = false;

        if (file != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Loading certs from: " + file);

            /* Check if wolfJCE WKS KeyStore is registered and available */
            wksAvailable = WolfSSLUtil.WKSAvailable();

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "wolfJCE WKS KeyStore type available: " + wksAvailable);

            /* Set KeyStore password if javax.net.ssl.keyStorePassword set */
            if (pass != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "javax.net.ssl.keyStorePassword system property " +
                    "set, using password");
                this.pswd = pass.toCharArray();
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "javax.net.ssl.keyStorePassword system property " +
                    "not set");
            }

            /* Keystore type given in property, try loading using it */
            if (type != null && !type.trim().isEmpty()) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "javax.net.ssl.keyStoreType set: " + type);

                if (requiredType != null && !requiredType.equals(type)) {
                    throw new KeyStoreException(
                        "javax.net.ssl.keyStoreType conflicts with required " +
                        "KeyStore type from wolfjsse.keystore.type.required");
                }

                sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                    file, this.pswd, type);
            }
            else {
                /* Try with wolfJCE WKS type first, in case wolfCrypt
                 * FIPS is being used */
                if (wksAvailable &&
                    (requiredType == null || requiredType.equals("WKS"))) {
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        file, this.pswd, "WKS");
                }

                /* Try with BKS, if we're running on Android */
                if ((sysStore == null) && WolfSSLUtil.isAndroid() &&
                    (requiredType == null || requiredType.equals("BKS"))) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Detected Android VM, trying BKS KeyStore type");
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        file, this.pswd, "BKS");
                }

                /* Try falling back to JKS */
                if (sysStore == null &&
                    (requiredType == null || requiredType.equals("JKS"))) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "javax.net.ssl.keyStoreType system property not set, " +
                    "trying type: JKS");
                    sysStore = WolfSSLUtil.LoadKeyStoreFileByType(
                        file, this.pswd, "JKS");
                }
            }

            if (sysStore == null) {
                throw new KeyStoreException(
                    "Failed to load KeyStore from System properties, " +
                    "please double check settings");
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Loaded certs from KeyStore via System properties");
            }
        }

        return sysStore;
    }

    @Override
    protected void engineInit(KeyStore store, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException {

        this.pswd = password;
        KeyStore certs = store;
        String requiredType = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entering engineInit(KeyStore store, char[] password)");

        requiredType = WolfSSLUtil.getRequiredKeyStoreType();
        if (requiredType != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "java.security has restricted KeyStore type");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "wolfjsse.keystore.type.required = " + requiredType);
        }

        /* If no KeyStore passed in, try to load from system property values
         * if they have been set */
        if (store == null) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "input KeyStore null, trying to load KeyStore from " +
                "system properties");

            certs = LoadKeyStoreFromSystemProperties(requiredType);
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "input KeyStore provided, using inside KeyManager");
        }

        /* Verify KeyStore we got matches our requirements, for example
         * type may be restricted by users trying to conform to FIPS
         * requirements */
        if (certs != null) {
            WolfSSLUtil.checkKeyStoreRequirements(certs);
        }

        this.store = certs;
        this.initialized = true;
    }

    @Override
    protected void engineInit(ManagerFactoryParameters arg0)
        throws InvalidAlgorithmParameterException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entering engineInit(ManagerFactoryParameters arg0)");

        throw new UnsupportedOperationException(
                "KeyManagerFactory.init(ManagerFactoryParameters) not " +
                "supported yet");
    }

    @Override
    protected KeyManager[] engineGetKeyManagers()
        throws IllegalStateException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered engineGetKeyManagers()");

        if (!this.initialized) {
            throw new IllegalStateException("KeyManagerFactory must be " +
                    "initialized before use, please call init()");
        }

        KeyManager[] km = {new WolfSSLKeyX509(this.store, this.pswd)};
        return km;
    }
}

