/* WolfSSLTrustX509.java
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

import com.wolfssl.WolfSSL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.Enumeration;
import java.net.Socket;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.StandardConstants;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;

import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLCertManager;
import com.wolfssl.WolfSSLException;
import java.security.cert.Certificate;

/**
 * wolfSSL implementation of X509TrustManager, extends
 * X509ExtendedTrustManager for additional hostname verification for HTTPS.
 *
 * @author wolfSSL
 */
public final class WolfSSLTrustX509 extends X509ExtendedTrustManager
    implements X509TrustManager {

    private KeyStore store = null;

    /**
     * Create new WolfSSLTrustX509 object
     *
     * @param in KeyStore to use with this X509TrustManager
     */
    public WolfSSLTrustX509(KeyStore in) {
        this.store = in;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLTrustX509");
    }

    /**
     * Sort provided certificate chain by subject and issuer.
     *
     * Begin with leaf cert, end with last most intermediate cert. Current
     * routine assumes that peer cert will be first in the provided certs
     * array, and will use that as a base/starting point to sort intermediate
     * certs going up the chain.
     *
     * @param certs Peer certificate chain, assuming leaf/peer is first
     *
     * @return List of X509Certifiates representing peer cert chain, sorted
     *         from leaf to last intermediate. Not including root CA.
     * @throws CertificateException if error occurs while building chain.
     */
    private X509Certificate[] sortCertChainBySubjectIssuer(
            X509Certificate[] certs) throws CertificateException {

        int i, curr, next;
        boolean nextFound = false;
        X509Certificate[] chain = null;
        X509Certificate[] retChain = null;

        if (certs == null) {
            throw new CertificateException("Input cert chain null");
        }

        /* If certs array is only one cert (peer), just return copy of it */
        if (certs.length == 1) {
            return certs.clone();
        }

        /* Make copy of peer cert chain, so we don't change original */
        chain = certs.clone();

        /* Print out chain for debugging */
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "sorting peer chain (" + chain.length + " certs):");
        for (i = 0; i < chain.length; i++) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "\t[" + i + "]: subject: " +
                chain[i].getSubjectX500Principal().getName());
        }

        /* Assume peer/leaf cert is first in array */
        for (curr = 0; curr < chain.length; curr++) {
            nextFound = false;
            for (next = curr + 1; next < chain.length; next++) {
                /* check if next subject matches curr issuer */
                if (chain[curr].getIssuerX500Principal().equals(
                    chain[next].getSubjectX500Principal())) {
                    /* if next not directly after curr, swap */
                    if (next != curr + 1) {
                        X509Certificate tmp = chain[next];
                        chain[next] = chain[curr + 1];
                        chain[curr + 1] = tmp;
                    }
                    nextFound = true;
                    break;
                }
            }

            /* if next not found, stop building chain */
            if (nextFound == false) {
                break;
            }
        }

        /* Print out sorted peer chain for debugging */
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "sorted peer chain (" + (curr + 1) + " certs):");
        for (i = 0; i <= curr; i++) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "\t[" + i + "]: subject: " +
                chain[i].getSubjectX500Principal().getName());
        }

        /* If chain is now shorter, return adjusted size array */
        if (chain.length > (curr + 1)) {
            retChain = Arrays.copyOf(chain, curr + 1);
        } else {
            retChain = chain;
        }

        return retChain;
    }

    /**
     * Finds and returns X509Certificate matching the root CA that will
     * verify the given leaf/intermediate certificate.
     *
     * This will search through the provided KeyStore for the approproate
     * root CA that correctly verifies the given certificate.
     *
     * @param cert Certificate for which to find verifying root CA
     * @param ks   KeyStore to search in for root CA
     *
     * @return X509Certificate representing root CA which will verify cert
     * @throws CertificateException on error/failure getting root CA.
     */
    private X509Certificate findRootCAFromKeyStoreForCert(X509Certificate cert,
        KeyStore ks) throws CertificateException {

        int i = 0;
        int ret;
        int verifiedRootIdx = -1;
        WolfSSLCertManager cm = null;
        List<X509Certificate> possibleCerts = new ArrayList<X509Certificate>();
        byte[] encodedRoot = null;
        byte[] encodedCert = null;
        boolean rootFound = false;

        if (cert == null || ks == null) {
            throw new CertificateException("Certificate or KeyStore is null");
        }

        /* Issuer name we need to match */
        X500Principal issuer = cert.getIssuerX500Principal();
        if (issuer == null) {
            throw new CertificateException("Unable to get expected issuer");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Searching KeyStore for root CA matching: " + issuer.getName());

        /* Find all issuers that match needed issuer name */
        try {
            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String name = aliases.nextElement();
                X509Certificate root = null;

                if (ks.isKeyEntry(name)) {
                    Certificate[] chain = ks.getCertificateChain(name);
                    if (chain != null) {
                        root = (X509Certificate) chain[0];
                    }
                } else {
                    root = (X509Certificate) ks.getCertificate(name);
                }

                if (root != null && root.getBasicConstraints() >= 0) {
                    if (root.getSubjectX500Principal().equals(issuer)) {
                        /* Found correct CN, add to possible roots list */
                        possibleCerts.add(root);
                    }
                }
            }
        } catch (KeyStoreException ex) {
            throw new CertificateException(ex);
        }

        if (possibleCerts.size() == 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "No root CA found in KeyStore to validate certificate");
            return null;
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Found " + possibleCerts.size() + " possible root CAs, testing");

        /* Use wolfSSL Cert Manager to make sure root verifies input cert */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfSSLException e) {
            throw new CertificateException(
                "Failed to create native WolfSSLCertManager");
        }

        for (i = 0; i < possibleCerts.size(); i++) {

            /* load candidate root CA as trusted */
            encodedRoot = possibleCerts.get(i).getEncoded();
            ret = cm.CertManagerLoadCABuffer(encodedRoot, encodedRoot.length,
                WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException("Failed to load root CA DER" +
                    "into wolfSSL cert manager");
            }

            /* try to verify input cert */
            encodedCert = cert.getEncoded();
            ret = cm.CertManagerVerifyBuffer(encodedCert, encodedCert.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Potential root " + i + " did not verify cert");
            } else {
                rootFound = true;
                verifiedRootIdx = i;
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Found valid root: " +
                    possibleCerts.get(i).getSubjectX500Principal().getName());
            }

            /* unload CAs from WolfSSLCertManager */
            ret = cm.CertManagerUnloadCAs();
            if (ret != WolfSSL.SSL_SUCCESS) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Error unloading root CAs from WolfSSLCertManager");
                cm.free();
                throw new CertificateException("Failed to unload root CA " +
                    "from WolfSSLCertManager");
            }

            if (rootFound == true) {
                break;
            }
        }

        /* Free native WolfSSLCertManager resources */
        cm.free();

        if (rootFound == true) {
            return possibleCerts.get(verifiedRootIdx);
        }

        return null;
    }

    /**
     * Verify cert chain using WolfSSLCertManager.
     * Do all loading and verification in one function to avoid holding native
     * resources at the object/class level.
     *
     * @param certs       Certificate chain to validate
     * @param type        Authentication type
     * @param returnChain Boolean (true/false), return validation chain or not
     *
     * @return Complete chain used for validation, including root CA, if
     * returnChain is true. Otherwise, if returnChain is false return NULL
     * @throws CertificateException on verification error/failure
     */
    private List<X509Certificate> certManagerVerify(
        X509Certificate[] certs, String type, boolean returnChain)
        throws CertificateException {

        int ret;
        WolfSSLCertManager cm = null;
        X509Certificate[] sortedCerts = null;

        X509Certificate rootCA = null;
        List<X509Certificate> fullChain = null;

        if (certs == null || certs.length == 0 ||
            type == null || type.length() == 0) {
            throw new CertificateException();
        }

        /* create new WolfSSLCertManager */
        try {
            cm = new WolfSSLCertManager();
        } catch (WolfSSLException e) {
            throw new CertificateException(
                "Failed to create native WolfSSLCertManager");
        }

        /* load trusted certs from KeyStore */
        try {
            ret = cm.CertManagerLoadCAKeyStore(this.store);
            if (ret != WolfSSL.SSL_SUCCESS) {
                throw new CertificateException(
                    "Failed to load trusted certs into WolfSSLCertManager");
            }
        } catch (WolfSSLException e) {
            cm.free();
            throw new CertificateException(
                "Failed to load trusted certs into WolfSSLCertManager");
        }

        /* Sort cert chain in order from peer to last intermedate. We
         * assume cert chain starts with peer certificate (certs[0]). */
        sortedCerts = sortCertChainBySubjectIssuer(certs);

        /* Walk backwards down list of intermediate CA certs, verify each one
         * based on trusted certs we already have loaded in the CertManager,
         * then once verified load the intermediate into the CertManager
         * as a root that can be used to verify our peer cert. */

        for (int i = sortedCerts.length-1; i > 0; i--) {

            /* Verify chain cert */
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Verifying intermediate chain cert: " +
                sortedCerts[i].getSubjectX500Principal().getName());

            byte[] encoded = sortedCerts[i].getEncoded();
            ret = cm.CertManagerVerifyBuffer(encoded, encoded.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException("Failed to verify " +
                    "intermediate chain cert");
            }

            /* Load chain cert as trusted CA */
            ret = cm.CertManagerLoadCABuffer(encoded, encoded.length,
                    WolfSSL.SSL_FILETYPE_ASN1);
            if (ret != WolfSSL.SSL_SUCCESS) {
                cm.free();
                throw new CertificateException("Failed to load intermediate " +
                    "CA certificate as trusted root");
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Loaded intermediate CA: " +
                sortedCerts[i].getSubjectX500Principal().getName());
        }

        /* Verify peer certificate */
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Verifying peer certificate: " +
            sortedCerts[0].getSubjectX500Principal().getName());

        byte[] peer = sortedCerts[0].getEncoded();
        if (peer == null) {
            cm.free();
            throw new CertificateException("Failed to get encoded peer cert");
        }

        ret = cm.CertManagerVerifyBuffer(peer, peer.length,
                WolfSSL.SSL_FILETYPE_ASN1);
        if (ret != WolfSSL.SSL_SUCCESS) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Failed to verify peer certificate");
            cm.free();
            throw new CertificateException("Failed to verify peer certificate");
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "Verified peer certificate: " +
            sortedCerts[0].getSubjectX500Principal().getName());

        cm.free();

        if (returnChain == true) {
            /* Find root CA from KeyStore to append to chain */
            rootCA = findRootCAFromKeyStoreForCert(
                        sortedCerts[sortedCerts.length - 1], this.store);
            if (rootCA == null) {
                throw new CertificateException("Unable to find root CA " +
                    "in KeyStore to append to chain list");
            }

            fullChain = new ArrayList<X509Certificate>();
            fullChain.addAll(Arrays.asList(sortedCerts));
            if (!fullChain.contains(rootCA)) {
                fullChain.add(rootCA);
            }
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Not returning cert chain from verify, not requested");
        }

        return fullChain;
    }

    /**
     * Verify hostname using HTTPS verification method.
     *
     * This method does the following operations in an attempt to verify
     * the HTTPS type hostname:
     *
     *   1. If SNI name has been received during TLS handshake, try to
     *      first verify peer certificate against that. Skip this step when
     *      on server side verifying the client, since server does not set
     *      an SNI for the client.
     *   2. Otherwise, try to verify certificate against SSLSocket
     *      hostname (SSLSession.getHostName()).
     *   3. If both of the above fail, fail hostname verification.
     *
     * @param cert peer certificate
     * @param socket SSLSocket associated with connection to peer. Only one
     *               of socket or engine params should be used. The other should
     *               be set to null.
     * @param engine SSLEngine associated with connection to peer. Either/or
     *               between this and socket param. Other should be set to
     *               null.
     * @param isClient true if we are calling this from client side, otherwise
     *               false if calling from server side.
     * @throws CertificateException if hostname cannot be verified
     */
    private void verifyHTTPSHostname(X509Certificate cert, SSLSocket socket,
        SSLEngine engine, boolean isClient) throws CertificateException {

        String peerHost = null;
        List<SNIServerName> sniNames = null;
        String sniHostName = null;
        SSLSession session = null;
        WolfSSLCertificate peerCert = null;
        int ret = WolfSSL.SSL_FAILURE;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "verifying HTTPS hostname");

        /* Get session associated with SSLSocket or SSLEngine */
        try {
            if (socket != null) {
                session = socket.getHandshakeSession();
            }
            else if (engine != null) {
                session = engine.getHandshakeSession();
            }
        } catch (UnsupportedOperationException e) {
            e.printStackTrace();
            throw new CertificateException(e);
        }

        /* Get peer host from SSLSocket */
        if (session != null) {
            peerHost = session.getPeerHost();
        }

        /* Get SNI name if SSLSocket has received that from peer. Only check
         * this when on the client side and verifying a server since SNI
         * holding expected server name is available on client-side but not
         * vice-versa */
        if (session != null && isClient &&
            (session instanceof ExtendedSSLSession)) {
            sniNames = ((ExtendedSSLSession)session).getRequestedServerNames();

            for (SNIServerName name : sniNames) {
                if (name.getType() == StandardConstants.SNI_HOST_NAME) {
                    SNIHostName tmpName = new SNIHostName(name.getEncoded());
                    if (tmpName != null) {
                        /* Get SNI name as ASCII string for comparison */
                        sniHostName = tmpName.getAsciiName();
                    }
                }
            }
        }

        /* Create new WolfSSLCertificate (WOLFSSL_X509) from
         * DER encoding of peer certificate */
        try {
            peerCert = new WolfSSLCertificate(cert.getEncoded());
            if (peerCert == null) {
                throw new CertificateException(
                    "Unable to create WolfSSLCertificate from peer cert");
            }

        } catch (WolfSSLException e) {
            throw new CertificateException(e);
        }

        /* Try verifying hostname against SNI name */
        if (isClient) {
            if (sniHostName != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "trying hostname verification against SNI: " + sniHostName);

                ret = peerCert.checkHost(sniHostName);
                if (ret == WolfSSL.SSL_SUCCESS) {
                    /* Hostname successfully verified against SNI name */
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "successfully verified X509 hostname using SNI name");
                    return;
                }
                else {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "hostname match with SNI failed");
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "no provided SNI name found");
            }
        }

        /* Try verifying hostname against peerHost from SSLSocket/Engine */
        if (peerHost != null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "trying hostname verification against peer host: " +
                peerHost);

            ret = peerCert.checkHost(peerHost);
            if (ret == WolfSSL.SSL_SUCCESS) {
                /* Hostname successfully verified against peer host name */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "successfully verified X509 hostname using SSLSession " +
                    "getPeerHost()");
                return;
            }
        }

        if (isClient) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "hostname verification failed for server peer cert, " +
                "tried SNI (" + sniHostName + "), peer host (" + peerHost +
                ")\n" + peerCert);
        } else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "hostname verification failed for client peer cert, " +
                "tried peer host (" + peerHost + ")\n" + peerCert);
        }

        throw new CertificateException("Hostname verification failed");
    }

    /**
     * Verify hostname of certificate.
     *
     * @param cert peer certificate
     * @param socket SSLSocket associated with connection to peer. Only one
     *               of socket or engine params should be used. The other should
     *               be set to null.
     * @param engine SSLEngine associated with connection to peer. Either/or
     *               between this and socket param. Other should be set to
     *               null.
     * @param isClient true if we are calling this from client side, otherwise
     *               false if calling from server side.
     * @throws CertificateException if hostname cannot be verified
     */
    protected void verifyHostname(X509Certificate cert,
        Socket socket, SSLEngine engine, boolean isClient)
        throws CertificateException {

        String endpointIdAlgo = null;
        SSLParameters sslParams = null;
        SSLSession session = null;

        /* Hostname verification only done if Socket is of SSLSocket,
         * not null, and connected */
        if ((socket != null) && (socket instanceof SSLSocket) &&
            (socket.isConnected())) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "entered verifyHostname, using SSLSocket for host info");

            sslParams = ((SSLSocket)socket).getSSLParameters();
            if (sslParams == null) {
                throw new CertificateException(
                    "SSLParameters in SSLSocket is null");
            }
            endpointIdAlgo = sslParams.getEndpointIdentificationAlgorithm();

            /* If endpoint ID algo is null or empty, skips hostname verify */
            if (endpointIdAlgo != null && !endpointIdAlgo.isEmpty()) {
                if (endpointIdAlgo.equals("HTTPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "verifying hostname, endpoint identification " +
                        "algorithm = HTTPS");
                    verifyHTTPSHostname(cert, (SSLSocket)socket,
                        null, isClient);
                }
                else {
                    throw new CertificateException(
                        "Unsupported Endpoint Identification Algorithm: " +
                        endpointIdAlgo);
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "endpoint Identification algo is null or empty, " +
                    "skipping hostname verification");
            }
        }
        else if (engine != null) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "entered verifyHostname, using SSLEngine for host info");

            sslParams = engine.getSSLParameters();
            if (sslParams == null) {
                throw new CertificateException(
                    "SSLParameters in SSLEngine is null");
            }
            endpointIdAlgo = sslParams.getEndpointIdentificationAlgorithm();

            /* If endpoint ID algo is null or empty, skips hostname verify */
            if (endpointIdAlgo != null && !endpointIdAlgo.isEmpty()) {
                if (endpointIdAlgo.equals("HTTPS")) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "verifying hostname, endpoint identification " +
                        "algorithm = HTTPS");
                    verifyHTTPSHostname(cert, null, engine, isClient);
                }
                else {
                    throw new CertificateException(
                        "Unsupported Endpoint Identification Algorithm: " +
                        endpointIdAlgo);
                }
            }
            else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "endpoint Identification algo is null or empty, " +
                    "skipping hostname verification");
            }
        }
        else {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "Socket is null, not connected, or not SSLSocket. " +
                "SSLEngine is also null. " +
                "Skipping hostname verification in ExtendedX509TrustManager");
        }
    }

    /**
     * Try to build and validate the client certificate chain based on the
     * provided certificates and authentication type.
     *
     * Does not do hostname verification internally. Calling applications are
     * responsible for checking hostname for accuracy if desired. To use
     * internal hostname verification use X509ExtendedTrustManager APIs
     * (for HTTPS verification).
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type)
            throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkClientTrusted()");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkClientTrusted(), success");
    }

    /**
     * Try to build and validate the client certificate chain based on the
     * provided certificates and authentication type.
     *
     * Also does hostname verification internally if Endpoint Identification
     * Algorithm has been set by application in SSLParameters, and that
     * Algorithm matches "HTTPS". If that is set, hostname verification is
     * done using SNI first then peer host value.
     *
     * Other Endpoint Identification Algorithms besides "HTTPS" are not
     * currently supported.
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type,
        Socket socket) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkClientTrusted() with Socket");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], socket, null, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkClientTrusted(Socket), success");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] certs, String type,
        SSLEngine engine) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkClientTrusted() with SSLEngine");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], null, engine, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkClientTrusted(SSLEngine), success");
    }

    /**
     * Try to build and validate the server certificate chain based on the
     * provided certificates and authentication type.
     *
     * Does not do hostname verification internally. Calling applications are
     * responsible for checking hostname for accuracy if desired. To use
     * internal hostname verification use X509ExtendedTrustManager APIs
     * (for HTTPS verification).
     *
     * @param certs peer certificate chain
     * @param type authentication type based on the client certificate
     * @throws CertificateException if certificate chain is not trusted
     */
    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type)
        throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkServerTrusted()");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkServerTrusted(certs, type), success");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type,
        Socket socket) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkServerTrusted() with Socket");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], socket, null, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkServerTrusted(certs, type, Socket), success");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] certs, String type,
        SSLEngine engine) throws CertificateException, IllegalArgumentException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkServerTrusted() with SSLEngine");

        if (certs == null) {
            throw new IllegalArgumentException("Input cert chain null");
        }

        if (type == null || type.length() == 0) {
            throw new IllegalArgumentException("Input auth type null");
        }

        /* Verify cert chain, throw CertificateException if not valid */
        certManagerVerify(certs, type, false);

        /* Verify hostname if right criteria matches */
        verifyHostname(certs[0], null, engine, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkServerTrusted(certs, type, SSLEngine), success");
    }

    /**
     * Verifies a specified certificate chain.
     * Non standard API, this is called/needed on some versions of Android.
     *
     * @param certs Certificate chain to validate
     * @param type  Authentication type
     * @param host  Hostname of the server. Cert pinning at this level not
     *              currently supported by wolfJSSE. If supported, and host was
     *              non-null, would check if chain is pinned correctly for
     *              this host.
     *
     * @throws CertificateException if chain does not verify properly
     * @return Certificate chain used for verification, ordered with leaf/peer
     *         cert first, root CA cert last
     */
    public List<X509Certificate> checkServerTrusted(X509Certificate[] certs,
        String type, String host) throws CertificateException {

        List<X509Certificate> certList = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkServerTrusted(cert, type, host)");

        certList = certManagerVerify(certs, type, true);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "leaving checkServerTrusted(certs, type, host), success");

        return certList;
    }

    /**
     * Returns an array of certificate authorities which are trusted for
     * authenticating peers.
     *
     * @return array of X509Certificate objects representing trusted
     *         CA certificates. May be empty (non-null).
     */
    @Override
    public X509Certificate[] getAcceptedIssuers() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getAcceptedIssuers()");

        if (store == null) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.ERROR,
                    "Trust Manager was not initialized");
            return new X509Certificate[0];
        }

        try {
            List<X509Certificate> CAs = new ArrayList<X509Certificate>();
            /* Store the alias of all CAs */
            Enumeration<String> aliases = store.aliases();
            while (aliases.hasMoreElements()) {
                final String name = aliases.nextElement();
                X509Certificate cert = null;

                if (store.isKeyEntry(name)) {
                    Certificate[] chain = store.getCertificateChain(name);
                    if (chain != null)
                        cert = (X509Certificate) chain[0];
                } else {
                    cert = (X509Certificate) store.getCertificate(name);
                }

                /* Add certificate entry as trusted if either:
                 * 1. X509v3 Basic Constraint CA:TRUE is set, or
                 * 2. Native wolfSSL has been compiled with
                 *    WOLFSSL_TRUST_PEER_CERT defined.
                 * SunJSSE implementation just adds all certificate entries
                 * it finds in the provided KeyStore as trusted, so this
                 * behavior does vary slightly from the default Sun
                 * implementation. */
                if (cert != null &&
                    (cert.getBasicConstraints() >= 0) ||
                    (WolfSSL.trustPeerCertEnabled())) {
                    CAs.add(cert);
                }
            }

            return CAs.toArray(new X509Certificate[CAs.size()]);

        } catch (KeyStoreException ex) {
            return new X509Certificate[0];
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable {
        this.store = null;
        super.finalize();
    }
}

