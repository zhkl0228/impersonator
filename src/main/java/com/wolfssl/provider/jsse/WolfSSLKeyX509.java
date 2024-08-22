/* WolfSSLKeyX509.java
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

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * wolfSSL implementation of X509KeyManager, extends X509ExtendedKeyManager
 * for implementation of chooseEngineClientAlias() and
 * chooseEngineServerAlias().
 *
 * @author wolfSSL
 */
public class WolfSSLKeyX509 extends X509ExtendedKeyManager
    implements X509KeyManager {

    private KeyStore store;
    private char[] password;

    /**
     * Create new WolfSSLKeyX509 object
     *
     * @param in input KeyStore to use with this object
     * @param password input KeyStore password
     */
    public WolfSSLKeyX509(KeyStore in, char[] password) {
        this.store = in;
        this.password = password;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "creating new WolfSSLKeyX509 object");
    }

    /**
     * Return array of aliases from current KeyStore that matches provided
     * type and issuers array.
     *
     * Returns:
     * null - if current KeyStore is null, error getting aliases from store,
     *        or no alias mathes found in current KeyStore.
     * String[] - aliases, if found that match type and/or issuers
     */
    private String[] getAliases(String type, Principal[] issuers) {
        Enumeration<String> aliases = null;
        int i;
        ArrayList<String> ret = new ArrayList<String>();

        if (store == null) {
            return null;
        }

        try {
            aliases = this.store.aliases();
        } catch (KeyStoreException ex) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                             "Error getting aliases from current KeyStore");
            return null;
        }

        /* loop through each alias in KeyStore */
        while (aliases.hasMoreElements()) {
            String current = aliases.nextElement();
            X509Certificate cert = null;
            try {
                cert = (X509Certificate)this.store.getCertificate(current);
            } catch (KeyStoreException ex) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                                 "Error getting certificate from KeyStore " +
                                 "for alias: " + current +
                                 ", continuing to next alias");
                continue;
            }

            if (type != null && cert != null &&
                !cert.getPublicKey().getAlgorithm().equals(type)) {

                /* free native memory early if X509Certificate is WolfSSLX509 */
                if (cert instanceof WolfSSLX509) {
                    ((WolfSSLX509)cert).free();
                }
                cert = null;

                /* different public key type, skip */
                continue;
            }

            /* if issuers is null then it does not matter which issuer */
            if (issuers == null) {
                ret.add(current);
            }
            else {
                if (cert != null) {
                    /* search through issuers for matching issuer name */
                    for (i = 0; i < issuers.length; i++) {
                        String certIssuer = cert.getIssuerDN().getName();
                        String issuerName = issuers[i].getName();

                        /* normalize spaces after commas, needed on some JDKs */
                        certIssuer = certIssuer.replaceAll(", ", ",");
                        issuerName = issuerName.replaceAll(", ", ",");

                        if (certIssuer.equals(issuerName)) {
                            /* matched issuer, add alias and continue on */
                            ret.add(current);
                            break;
                        }
                    }
                }
            }
        } /* end while */

        if (ret.size() == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "No aliases found in KeyStore that match type and/or issuer");
            return null;
        }

        return ret.toArray(new String[0]);
    }

    @Override
    public String[] getClientAliases(String type, Principal[] issuers) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getClientAliases()");

        return getAliases(type, issuers);
    }

    /* Note: Socket argument not used by wolfJSSE to choose aliases */
    @Override
    public String chooseClientAlias(String[] type, Principal[] issuers,
        Socket sock) {

        int i;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered chooseClientAlias()");

        if (type == null) {
            return null;
        }

        for (i = 0; i < type.length; i++) {
            String[] all = getAliases(type[i], issuers);
            if (all != null) {
                return all[0];
            }
        }
        return null;
    }

    /* Note: Engine argument not yet used by wolfJSSE to choose aliases */
    @Override
    public String chooseEngineClientAlias(String[] type, Principal[] issuers,
        SSLEngine engine) {

        int i;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered chooseEngineClientAlias()");

        if (type == null) {
            return null;
        }

        for (i = 0; i < type.length; i++) {
            String[] all = getAliases(type[i], issuers);
            if (all != null) {
                return all[0];
            }
        }
        return null;
    }

    @Override
    public String[] getServerAliases(String type, Principal[] issuers) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getServerAliases(), type: " + type);

        return getAliases(type, issuers);
    }

    @Override
    public String chooseServerAlias(String type, Principal[] issuers,
        Socket sock) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered chooseServerAlias(), type: " + type);

        if (type == null || type.isEmpty()) {
            return null;
        }

        /* For now using same behavior as chooseClientAlias() */
        return chooseClientAlias(new String[] {type}, issuers, sock);
    }

    @Override
    public String chooseEngineServerAlias(String type, Principal[] issuers,
        SSLEngine engine) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered chooseEngineServerAlias(), type: " + type);

        if (type == null || type.isEmpty()) {
            return null;
        }

        /* For now, using same behavior as chooseEngineClientAlias() */
        return chooseEngineClientAlias(new String[] {type}, issuers, engine);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {

        X509Certificate[] ret = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getCertificateChain(), alias: " + alias);

        if (store == null || alias == null) {
            return null;
        }

        try {
            Certificate[] certs = this.store.getCertificateChain(alias);
            if (certs != null) {
                int x509Cnt = 0;

                /* count up X509Certificate type in certs[] */
                for (int i = 0; i < certs.length; i++) {
                    if (certs[i] instanceof X509Certificate) {
                        x509Cnt++;
                    }
                }

                /* store into X509Certificate array */
                ret = new X509Certificate[x509Cnt];
                for (int i = 0; i < certs.length; i++) {
                    if (certs[i] instanceof X509Certificate) {
                        ret[i] = (X509Certificate)certs[i];
                    }
                }
            }

        } catch (KeyStoreException ex) {
            return null;
        }

        return ret;
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {

        PrivateKey key = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getPrivateKey(), alias: " + alias);

        try {
            key = (PrivateKey)store.getKey(alias, password);
        } catch (Exception e) {
           /* @TODO unable to get key */
        }
        return key;
    }
}

