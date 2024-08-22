/* WolfSSLX509.java
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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;
import java.util.TreeSet;
import java.util.List;
import java.util.Collection;

import com.wolfssl.WolfSSLCertificate;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * wolfSSL implementation of X509Certificate
 *
 * @author wolfSSL
 */
public class WolfSSLX509 extends X509Certificate {

    /** Inner WolfSSLCertificate object */
    private WolfSSLCertificate cert = null;
    /** Certificate extension OID values */
    private String[] extensionOid = {
        "2.5.29.15", /* key usage */
        "2.5.29.19", /* basic constraint */
        "2.5.29.17", /* subject alt names */
        "2.5.29.14", /* subject key ID */
        "2.5.29.35", /* auth key ID */
        "2.5.29.31"  /* CRL dist */
    };

    /**
     * Create new WolfSSLX509 object
     *
     * @param der ASN.1/DER encoded X.509 certificate
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509(byte[] der) throws WolfSSLException{
        super();
        this.cert = new WolfSSLCertificate(der);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509(byte[] der)");
    }

    /**
     * Create new WolfSSLX509 object
     *
     * @param derName ASN.1/DER X.509 certificate file name to load
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509(String derName) throws WolfSSLException {
        super();
        this.cert = new WolfSSLCertificate(derName);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509(String derName)");
    }

    /**
     * Create new WolfSSLX509 object
     *
     * @param x509 initialized pointer to native WOLFSSL_X509 struct
     * @param doFree should this WOLFSSL_X509 structure be freed when free()
     *        is called? true to free memory, false to skip free. Free
     *        should be skipped if caller is controlling memory for this
     *        WOLFSSL_X509 struct pointer.
     *
     * @throws WolfSSLException if certificate parsing fails
     */
    public WolfSSLX509(long x509, boolean doFree) throws WolfSSLException {
        super();
        this.cert = new WolfSSLCertificate(x509, doFree);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLX509(long x509, boolean doFree)");
    }

    @Override
    public void checkValidity()
        throws CertificateExpiredException, CertificateNotYetValidException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkValidity()");

        this.checkValidity(new Date());
    }

    @Override
    public void checkValidity(Date date)
        throws CertificateExpiredException, CertificateNotYetValidException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered checkValidity(Date date)");

        if (this.cert == null) {
            throw new CertificateExpiredException();
        }

        Date after = this.cert.notAfter();
        Date before = this.cert.notBefore();

        if (date.after(after)) {
            throw new CertificateExpiredException();
        }
        if (date.before(before)) {
            throw new CertificateNotYetValidException();
        }
    }

    @Override
    public int getVersion() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getVersion()");

        if (this.cert == null) {
            return 0;
        }
        return this.cert.getVersion();
    }

    @Override
    public BigInteger getSerialNumber() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSerialNumber()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getSerial();
    }

    @Override
    public Principal getIssuerDN() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getIssuerDN()");

        if (this.cert == null) {
            return null;
        }
        String name = this.cert.getIssuer();
        return new WolfSSLPrincipal(name);
    }

    @Override
    public Principal getSubjectDN() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSubjectDN()");

        if (this.cert == null) {
            return null;
        }
        String name = this.cert.getSubject();
        return new WolfSSLPrincipal(name);
    }

    @Override
    public Date getNotBefore() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNotBefore()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.notBefore();
    }

    @Override
    public Date getNotAfter() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNotAfter()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.notAfter();
    }

    @Override
    public byte[] getTBSCertificate() throws CertificateEncodingException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getTBSCertificate()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getTbs();
    }

    @Override
    public byte[] getSignature() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSignature()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getSignature();
    }

    @Override
    public String getSigAlgName() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSigAlgName()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getSignatureType();
    }

    @Override
    public String getSigAlgOID() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSigAlgOID()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getSignatureOID();
    }

    @Override
    public byte[] getSigAlgParams() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSigAlgParams()");

        throw new UnsupportedOperationException(
            "X509Certificate.getSigAlgParams() not supported yet");
    }

    @Override
    public boolean[] getIssuerUniqueID() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getIssuerUniqueID()");

        throw new UnsupportedOperationException(
            "X509Certificate.getIssuerUniqueID() not supported yet");
    }

    @Override
    public boolean[] getSubjectUniqueID() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSubjectUniqueID()");

        throw new UnsupportedOperationException(
            "X509Certificate.getSubjectUniqueID() not supported yet");
    }

    @Override
    public boolean[] getKeyUsage() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getKeyUsage()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getKeyUsage();
    }

    @Override
    public int getBasicConstraints() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getBasicConstraints()");

        if (this.cert == null) {
            return 0;
        }
        if (this.cert.isCA() == 1) {
            int pLen = this.cert.getPathLen();
            if (pLen == -1) { /* if not set then return max int value */
                return Integer.MAX_VALUE;
            }
            return pLen;
        }
        return -1;
    }

    @Override
    public byte[] getEncoded() throws CertificateEncodingException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEncoded()");

        if (this.cert == null) {
            return null;
        }

        try {
            byte[] ret = this.cert.getDer();
            if (ret == null) {
                throw new CertificateEncodingException();
            }
            return ret;

        } catch (WolfSSLJNIException e) {
            throw new CertificateEncodingException(e);
        }
    }

    @Override
    public Collection<List<?>> getSubjectAlternativeNames()
        throws CertificateParsingException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSubjectAlternativeNames()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getSubjectAltNames();
    }

    @Override
    public void verify(PublicKey key)
        throws CertificateException, NoSuchAlgorithmException,
               InvalidKeyException, SignatureException {
        byte[] pubKey;
        boolean ret;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered verify(PublicKey key)");

        if (key == null) {
            throw new InvalidKeyException();
        }
        if (this.cert == null) {
            throw new CertificateException();
        }
        pubKey = key.getEncoded();

        ret = this.cert.verify(pubKey, pubKey.length);
        if (ret != true) {
            throw new SignatureException();
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
        throws CertificateException, NoSuchAlgorithmException,
               InvalidKeyException, NoSuchProviderException,
               SignatureException {
        Signature sig;
        String sigOID;
        byte[] sigBuf;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered verify(PublicKey key, String sigProvider)");

        if (key == null || sigProvider == null) {
            throw new InvalidKeyException();
        }
        if (this.cert == null) {
            throw new CertificateException();
        }

        sigOID = this.getSigAlgName();
        sigBuf = this.getSignature();
        sig = Signature.getInstance(sigOID, sigProvider);
        if (sig == null || sigBuf == null) {
            throw new CertificateException();
        }

        sig.initVerify(key);
        sig.update(this.getTBSCertificate());
        if (sig.verify(sigBuf) == false) {
            throw new SignatureException();
        }
    }

    /* This method was added in Android API level 24 */
    /* @Override */
    public void verify(PublicKey key, Provider p)
            throws CertificateException, NoSuchAlgorithmException,
                   InvalidKeyException, SignatureException {
        Signature sig;
        String sigOID;
        byte[] sigBuf;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered verify(PublicKey key, Provider p)");

        if (key == null || p == null) {
            throw new InvalidKeyException();
        }
        if (this.cert == null) {
            throw new CertificateException();
        }

        sigOID = this.getSigAlgName();
        sigBuf = this.getSignature();

        sig = Signature.getInstance(sigOID, p);
        if (sig == null || sigBuf == null) {
            throw new CertificateException();
        }

        try {
            sig.initVerify(key);
            sig.update(this.getTBSCertificate());
        } catch (Exception e) {
            throw new CertificateException(e);
        }

        if (sig.verify(this.getSignature()) == false) {
            throw new SignatureException();
        }
    }

    @Override
    public String toString() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered toString()");

        if (this.cert == null) {
            /* return empty string instead of null */
            return "";
        }
        return this.cert.toString();
    }

    /**
     * Free native resources used by this object.
     */
    public void free() {
        try {
            if (this.cert != null) {
                this.cert.free();
                this.cert = null;
            }
        } catch (IllegalStateException e) {
            /* was already free'd */
        }
    }

    @Override
    public PublicKey getPublicKey() {

        String type = null;
        byte[] der = null;
        KeyFactory kf = null;
        PublicKey key = null;
        X509EncodedKeySpec spec = null;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getPublicKey()");

        if (this.cert == null) {
            return null;
        }

        type = this.cert.getPubkeyType();
        der = this.cert.getPubkey();

        try {
            if (type.equals("RSA")) {
                kf = KeyFactory.getInstance("RSA");
            } else if (type.equals("ECC")) {
                kf = KeyFactory.getInstance("EC");
            } else if (type.equals("DSA")) {
                kf = KeyFactory.getInstance("DSA");
            }

            if (kf != null) {
                spec = new X509EncodedKeySpec(der);
                key = (PublicKey)kf.generatePublic(spec);
            }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return null;
        }

        return key;
    }

    /* If unsupported critical extension is found then wolfSSL should not parse
     * the certificate. */
    @Override
    public boolean hasUnsupportedCriticalExtension() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered hasUnsupportedCriticalExtension()");

        /* @TODO further testing*/
        return false;
    }


    public Set<String> getCriticalExtensionOIDs() {
        int i;
        Set<String> ret = new TreeSet<String>();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getCriticalExtensionOIDs()");

        if (this.cert == null) {
            return null;
        }

        for (i = 0; i < this.extensionOid.length; i++) {
            if (this.cert.getExtensionSet(this.extensionOid[i]) == 2) {
                ret.add(this.extensionOid[i]);
            }
        }

        if (ret.size() == 0)
            return null;

        return ret;
    }


    public Set<String> getNonCriticalExtensionOIDs() {
        int i;
        Set<String> ret = new TreeSet<String>();

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNonCriticalExtensionOIDs()");

        if (this.cert == null) {
            return null;
        }

        for (i = 0; i < this.extensionOid.length; i++) {
            if (this.cert.getExtensionSet(this.extensionOid[i]) == 1) {
                ret.add(this.extensionOid[i]);
            }
        }

        return ret;
    }


    /* slight difference in that the ASN1 syntax is not returned.
     * i.e. no OCTET STRING Id "04 16 04 14" before subject key id */
    public byte[] getExtensionValue(String oid) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getExtensionValue()");

        if (this.cert == null) {
            return null;
        }
        return this.cert.getExtension(oid);
    }


    @SuppressWarnings("removal")
    @Override
    protected void finalize() throws Throwable {
        try {
            this.free();
        } finally {
            super.finalize();
        }
    }

    /* wolfSSL Principal class */
    private class WolfSSLPrincipal implements Principal {
        private String name;
        private String[] DNs = { "/emailAddress=", "/CN=", "/OU=",
                "/O=", "/L=", "/ST=", "/C="};

        /* replace the wolfSSL version of the tag. Returns replacement
         * on success. */
        private String getReplace(String in) {
            if (in.equals("/emailAddress=")) {
                return "EMAILADDRESS=";
            }
            if (in.equals("/CN=")) {
                return "CN=";
            }
            if (in.equals("/OU=")) {
                return "OU=";
            }
            if (in.equals("/O=")) {
                return "O=";
            }
            if (in.equals("/L=")) {
                return "L=";
            }
            if (in.equals("/ST=")) {
                return "ST=";
            }
            if (in.equals("/C=")) {
                return "C=";
            }
            return null;
        }

        /* check if the string starts with an expected tag.
         * returns index into DNs of tag when found */
        private int containsDN(String in) {
            int i;
            for (i = 0; i < DNs.length; i++) {
                if (in.startsWith(DNs[i]))
                    return i;
            }
            return -1;
        }

        /* convert name from having "/DN=" format to "DN= ," format
         * returns the new reformatted string on success */
        private String reformatList(String in) {
            String[] ret;
            int i, j;
            String tmp = in;
            ArrayList<String> list = new ArrayList<String>();

            if (in == null) {
                return null;
            }

            ret = in.split("/");

            while (tmp.length() > 3) {
                for (i = tmp.length() - 3; i >= 0; i--) {
                    if ((j = containsDN(in.substring(i))) >= 0) {
                        String current = tmp.substring(i, tmp.length());
                        current = current.replaceAll(DNs[j],
                                                     getReplace(DNs[j]));
                        list.add(current);
                        tmp = tmp.substring(0, i);
                        break;
                    }
                }
            }

            ret = list.toArray(new String[list.size()]);
            tmp = "";
            for (i = 0; i < ret.length - 1; i++) {
                tmp = tmp.concat(ret[i]);
                tmp = tmp.concat(", ");
            }
            tmp = tmp.concat(ret[i]);

            return tmp;
        }

        private WolfSSLPrincipal(String in) {
            this.name = reformatList(in);

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "created new WolfSSLPrincipal");
        }

        @Override
        public String getName() {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "entered getName()");

            return this.name;
        }

    }
}
