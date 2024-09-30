/* WolfSSLX509X.java
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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;
import javax.security.cert.*;

import com.wolfssl.WolfSSLException;

/**
 * javax version of certificates. Depreciated, WolfSSLX509 should be
 * used instead
 *
 * @author wolfSSL
 */
@SuppressWarnings("deprecation")
public class WolfSSLX509X extends X509Certificate {
    WolfSSLX509 cert;

    /**
     * Create new WolfSSLX509X object
     *
     * @param der ASN.1/DER encoded X.509 certificate
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509X(byte[] der) throws WolfSSLException{

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509X(byte[] der)");

        this.cert = new WolfSSLX509(der);
    }

    /**
     * Create new WolfSSLX509X object
     *
     * @param derName ASN.1/DER X.509 certificate file name to load
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509X(String derName) throws WolfSSLException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509X(String derName)");

        this.cert = new WolfSSLX509(derName);
    }

    /**
     * Create new WolfSSLX509X object
     *
     * @param x509 initialized pointer to native WOLFSSL_X509 struct
     * @param doFree should this WOLFSSL_X509 structure be freed when free()
     *        is called? true to free memory, false to skip free. Free
     *        should be skipped if caller is controlling memory for this
     *        WOLFSSL_X509 struct pointer.
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509X(long x509, boolean doFree) throws WolfSSLException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509X(long x509, boolean doFree)");

        this.cert = new WolfSSLX509(x509, doFree);
    }

    @Override
    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException {

        try {
            this.cert.checkValidity();
        } catch (java.security.cert.CertificateExpiredException ex) {
            throw new CertificateExpiredException();
        } catch (java.security.cert.CertificateNotYetValidException ex) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException {

        try {
            this.cert.checkValidity(date);
        } catch (java.security.cert.CertificateExpiredException ex) {
            throw new CertificateExpiredException();
        } catch (java.security.cert.CertificateNotYetValidException ex) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public int getVersion() {

        /* this returns the ASN.1 encoding for version
         * i.e. v1 (0) , v2 (1) , v3 (2). To get the correct value subtract 1
         * from the version returned by "cert" which is 1, 2, or 3 */
        return this.cert.getVersion() - 1;
    }

    @Override
    public BigInteger getSerialNumber() {
        return this.cert.getSerialNumber();
    }

    @Override
    public Principal getIssuerDN() {
        return this.cert.getIssuerDN();
    }

    @Override
    public Principal getSubjectDN() {
        return this.cert.getSubjectDN();
    }

    @Override
    public Date getNotBefore() {
        return this.cert.getNotBefore();
    }

    @Override
    public Date getNotAfter() {
        return this.cert.getNotAfter();
    }

    @Override
    public String getSigAlgName() {
        return this.cert.getSigAlgName();
    }

    @Override
    public String getSigAlgOID() {
        return this.cert.getSigAlgOID();
    }

    @Override
    public byte[] getSigAlgParams() {
        return this.cert.getSigAlgParams();
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {
        try {
            return this.cert.getEncoded();
        } catch (java.security.cert.CertificateEncodingException ex) {
            throw new CertificateEncodingException();
        }
    }

    @Override
    public void verify(PublicKey key)
        throws CertificateException, NoSuchAlgorithmException,
               InvalidKeyException, NoSuchProviderException,
               SignatureException {
        try {
            this.cert.verify(key);
        } catch (java.security.cert.CertificateException ex) {
            throw new CertificateException();
        }
    }

    @Override
    public void verify(PublicKey key, String provider)
        throws CertificateException, NoSuchAlgorithmException,
               InvalidKeyException, NoSuchProviderException,
               SignatureException {
        try {
            this.cert.verify(key, provider);
        } catch (java.security.cert.CertificateException ex) {
            throw new CertificateException();
        }
    }

    @Override
    public String toString() {
        return this.cert.toString();
    }

    @Override
    public PublicKey getPublicKey() {
        return this.cert.getPublicKey();
    }

    @Override
    @SuppressWarnings("removal")
    protected void finalize() throws Throwable {
        super.finalize();
        this.cert.free();
    }

}
