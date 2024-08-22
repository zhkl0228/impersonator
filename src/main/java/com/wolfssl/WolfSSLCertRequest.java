/* WolfSSLCertRequest.java
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

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;

/**
 * WolfSSLCertRequest class, wraps native X509_REQ functionality.
 */
public class WolfSSLCertRequest {

    private boolean active = false;

    /* native X509_REQ pointer */
    private long x509ReqPtr = 0;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native X509_REQ pointer use */
    private final Object x509ReqLock = new Object();

    /* Public key types used for CSR, mirrored from
     * native enum in wolfssl/openssl/evp.h */
    private static final int EVP_PKEY_RSA = 16;
    private static final int EVP_PKEY_EC  = 18;

    /* Define from <wolfssl/openssl/asn1.h> */
    private static final int MBSTRING_ASC = 0x1001;

    /* Native JNI methods */
    static native long X509_REQ_new();
    static native void X509_REQ_free(long x509ReqPtr);
    static native int X509_REQ_set_subject_name(long x509ReqPtr,
        long x509NamePtr);
    static native int X509_REQ_add1_attr_by_NID(long x509ReqPtr, int nid,
        int type, byte[] bytes);
    static native int X509_REQ_set_version(long x509ReqPtr, long ver);
    static native byte[] X509_REQ_print(long x509ReqPtr);
    static native int X509_REQ_sign(long x509ReqPtr, int evpKeyType,
        byte[] keyBytes, int format, String digestAlg);
    static native int X509_REQ_set_pubkey_native_open(long x509ReqPtr,
        int keyType, byte[] fileBytes, int format);
    static native byte[] X509_REQ_get_der(long x509);
    static native byte[] X509_REQ_get_pem(long x509);
    static native int X509_add_ext_via_nconf_nid(long x509Ptr, int nid,
        String extValue, boolean isCritical);
    static native int X509_add_ext_via_set_object_boolean(long x509Ptr,
        int nid, boolean extValue, boolean isCritical);

    /**
     * Create new empty WolfSSLCertRequest object, for use with CSR generation
     *
     * @throws WolfSSLException if native API call fails.
     */
    public WolfSSLCertRequest() throws WolfSSLException {

        x509ReqPtr = X509_REQ_new();
        if (x509ReqPtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertRequest");
        }

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Verifies that the current WolfSSLCertRequest object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLCertRequest object has been freed");
            }
        }
    }

    /**
     * Set the Subject Name to be used with this WolfSSLCertRequest.
     * Note that the WolfSSLX509Name object should be completely set up
     * before calling this method. This method copies/duplicates the contents
     * of the WOLFSSL_X509_NAME (WolfSSLX509Name) into the native
     * WOLFSSL_X509 structure.
     *
     * @param name Initialized and populated WolfSSLX509 name to be set into
     *        Subject Name of WolfSSLCertRequest for cert generation.
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void setSubjectName(WolfSSLX509Name name)
        throws IllegalStateException, WolfSSLException {

        int ret;

        confirmObjectIsActive();

        synchronized (x509ReqLock) {
            /* TODO somehow lock WolfSSLX509Name object while using pointer? */
            ret = X509_REQ_set_subject_name(this.x509ReqPtr,
                    name.getNativeX509NamePtr());
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting subject name " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Add a CSR attribute to this WolfSSLCertRequest
     *
     * @param nid NID of an attribute to add. Must be one of:
     *                WolfSSL.NID_pkcs9_challengePassword
     *                WolfSSL.NID_serialNumber
     *                WolfSSL.NID_pkcs9_unstructuredName
     *                WolfSSL.NID_pkcs9_contentType
     *                WolfSSL.NID_surname
     *                WolfSSL.NID_initials
     *                WolfSSL.NID_givenName
     *                WolfSSL.NID_dnQualifier
     * @param value value of attribute to set, if passing in String, use
     *        String.getBytes()
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void addAttribute(int nid, byte[] value)
        throws IllegalStateException, WolfSSLException {

        int ret;

        confirmObjectIsActive();

        if (nid != WolfSSL.NID_pkcs9_challengePassword &&
            nid != WolfSSL.NID_serialNumber &&
            nid != WolfSSL.NID_pkcs9_unstructuredName &&
            nid != WolfSSL.NID_pkcs9_contentType &&
            nid != WolfSSL.NID_surname &&
            nid != WolfSSL.NID_initials &&
            nid != WolfSSL.NID_givenName &&
            nid != WolfSSL.NID_dnQualifier) {
            throw new WolfSSLException(
                "Unsupported CSR attribute NID: " + nid);
        }

        if (value == null || value.length == 0) {
            throw new WolfSSLException(
                "CSR attribute value may not be null or zero length");
        }

        synchronized (x509ReqLock) {
            ret = X509_REQ_add1_attr_by_NID(this.x509ReqPtr, nid,
                MBSTRING_ASC, value);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting CSR attribute " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set CSR version for this WolfSSLCertRequest object.
     *
     * Calling this method is optional when generating a CSR. By default,
     * a value of 0 (zero) is used for the CSR version. This is currently
     * the version used by all CSR RFCs/specs.
     *
     * @param version version to set for CSR
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void setVersion(long version)
        throws IllegalStateException, WolfSSLException {

        int ret;

        confirmObjectIsActive();

        synchronized (x509ReqLock) {
            ret = X509_REQ_set_version(this.x509ReqPtr, version);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting CSR version " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set public key for this WolfSSLCertRequest, used when generating
     * Certificate Signing Requests
     *
     * @param filePath Path to public key file
     * @param keyType Type of public key algorithm, options are:
     *                WolfSSL.RSAk
     *                WolfSSL.ECDSAk
     * @param format Format of public key file, options are:
     *                WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *                WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws IOException on error opening input file
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void setPublicKey(String filePath, int keyType, int format)
        throws IllegalStateException, IOException, WolfSSLException {

        int ret = 0;
        File keyFile = null;
        byte[] fileBytes = null;

        confirmObjectIsActive();

        if (filePath == null || filePath.isEmpty()) {
            throw new WolfSSLException("File path is null or empty");
        }

        keyFile = new File(filePath);
        if (!keyFile.exists()) {
            throw new WolfSSLException("Input file does not exist: " +
                filePath);
        }

        fileBytes = WolfSSL.fileToBytes(keyFile);
        if (fileBytes == null) {
            throw new WolfSSLException("Failed to read bytes from file: " +
                filePath);
        }

        setPublicKey(fileBytes, keyType, format);
    }

    /**
     * Set public key for this WolfSSLCertRequest, used when generating
     * Certificate Signing Requests
     *
     * @param key Byte array containing public key
     * @param keyType Type of public key algorithm, options are:
     *                WolfSSL.RSAk
     *                WolfSSL.ECDSAk
     * @param format Format of public key file, options are:
     *                WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *                WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws IOException on error opening input file
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void setPublicKey(byte[] key, int keyType, int format)
        throws IllegalStateException, IOException, WolfSSLException {

        int ret = 0;
        int evpKeyType;

        confirmObjectIsActive();

        if (key == null || key.length == 0) {
            throw new WolfSSLException("Key array is null or empty");
        }

        if (format != WolfSSL.SSL_FILETYPE_ASN1 &&
            format != WolfSSL.SSL_FILETYPE_PEM) {
            throw new WolfSSLException(
                "Invalid key format, must be PEM or DER");
        }

        switch (keyType) {
            case WolfSSL.RSAk:
                evpKeyType = EVP_PKEY_RSA;
                break;
            case WolfSSL.ECDSAk:
                evpKeyType = EVP_PKEY_EC;
                break;
            default:
                throw new WolfSSLException("Unsupported public key type");
        }

        synchronized (x509ReqLock) {
            ret = X509_REQ_set_pubkey_native_open(this.x509ReqPtr, evpKeyType,
                    key, format);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting public key into native WOLFSSL_X509_REQ " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Set public key for this WolfSSLCertRequest, used when generating
     * Certificate Signing Requests
     *
     * @param key PublicKey object containing public key to be used when
     *            generating CSR.
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     * @throws IOException on error opening/reading public key
     */
    public void setPublicKey(PublicKey key)
        throws IllegalStateException, IOException, WolfSSLException {

        int keyType;
        byte[] encodedKey = null;

        confirmObjectIsActive();

        if (key instanceof RSAPublicKey) {
            keyType = WolfSSL.RSAk;
        }
        else if (key instanceof ECPublicKey) {
            keyType = WolfSSL.ECDSAk;
        }
        else {
            throw new WolfSSLException(
                "PublicKey must be of type RSAPublicKey or ECPublicKey");
        }

        /* Get DER encoded key */
        encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new WolfSSLException(
                "Error getting encoded (DER) format of PublicKey");
        }

        setPublicKey(encodedKey, keyType, WolfSSL.SSL_FILETYPE_ASN1);
    }

    /**
     * Add an extension to a WolfSSLCertRequest given the NID and extension
     * value String.
     *
     * This method supports the following extensions:
     *    - Key Usage (WolfSSL.NID_key_usage)
     *    - Extended Key Usage (WolfSSL.NID_ext_key_usage)
     *    - Subject Alt Name (WolfSSL.NED_subject_alt_name)
     *
     * @param nid NID of extension to add. Must be one of:
     *        WolfSSL.NID_key_usage
     *        WolfSSL.NID_ext_key_usage
     *        WolfSSL.NID_subject_alt_name
     * @param value String value of extension to set. For keyUsage and
     *              extKeyUsage this should be a comma-delimited list.
     *              For subjectAltName, this is a single value. Possible
     *              values for keyUsage and extKeyUsage are:
     *
     *              NID_key_usage:
     *                  digitalSignature
     *                  nonRepudiation
     *                  contentCommitment
     *                  keyEncipherment
     *                  dataEncipherment
     *                  keyAgreement
     *                  keyCertSign
     *                  cRLSign
     *                  encipherOnly
     *                  decipherOnly
     *
     *              NID_ext_key_usage:
     *                  serverAuth
     *                  clientAuth
     *                  codeSigning
     *                  emailProtection
     *                  timeStamping
     *                  OCSPSigning
     *
     * @param isCritical Boolean flag indicating if this extension is
     *        critical
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void addExtension(int nid, String value, boolean isCritical)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;

        confirmObjectIsActive();

        if (nid != WolfSSL.NID_key_usage &&
            nid != WolfSSL.NID_subject_alt_name &&
            nid != WolfSSL.NID_ext_key_usage) {
            throw new WolfSSLException(
                "Unsupported X509v3 extension NID: " + nid);
        }

        synchronized (x509ReqLock) {
            ret = X509_add_ext_via_nconf_nid(this.x509ReqPtr, nid, value,
                    isCritical);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            if ((WolfSSL.getLibVersionHex() <= 0x05006003) &&
                (nid == WolfSSL.NID_key_usage ||
                 nid == WolfSSL.NID_ext_key_usage)) {

                /* wolfSSL versions 5.6.3 and earlier did not include code
                 * fixes to native wolfSSL allowing this extension support to
                 * work. Use a version > 5.6.3 or apply patch from wolfSSL
                 * PR 6585 for correct support */
                throw new WolfSSLException(
                    "Error setting extension into native WOLFSSL_X509 " +
                    "(ret: " + ret + ").\nNeed to use wolfSSL version " +
                    "greater than 5.6.3 for extension support (PR 6585).");
            }

            throw new WolfSSLException(
                "Error setting extension into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Add an extension to a WolfSSLCertRequest given the NID and extension
     * value true/false value.
     *
     * This method supports the following extensions:
     *    - Basic Constraints (WolfSSL.NID_basic_constraints)
     *
     * @param nid NID of extension to add. Must be one of:
     *            WolfSSL.NID_basic_constraints
     * @param value Boolean value of extension (true/false)
     * @param isCritical Boolean flag indicating if this extension is
     *        critical
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void addExtension(int nid, boolean value, boolean isCritical)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;

        confirmObjectIsActive();

        if (nid != WolfSSL.NID_basic_constraints) {
            throw new WolfSSLException(
                "Unsupported X509v3 extension NID: " + nid);
        }

        synchronized (x509ReqLock) {
            ret = X509_add_ext_via_set_object_boolean(
                    this.x509ReqPtr, nid, value, isCritical);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting extension into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sign certificate request with private key from file.
     *
     * @param filePath Path to private key file
     * @param keyType Type of public key algorithm, options are:
     *            WolfSSL.RSAk
     *            WolfSSL.ECDSAk
     * @param format Format of private key file, options are:
     *            WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *            WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     * @param digestAlg Message digest algorithm to use for signature
     *        generation. Options include the following, but native algorithm
     *        must be compiled into wolfSSL to be available:
     *            "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
     *            "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws IOException on error opening input file
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signRequest(String filePath, int keyType, int format,
        String digestAlg) throws IllegalStateException, IOException,
                              WolfSSLException {

        int ret = 0;
        File keyFile = null;
        byte[] fileBytes = null;

        confirmObjectIsActive();

        if (filePath == null || filePath.isEmpty()) {
            throw new WolfSSLException("File path is null or empty");
        }

        keyFile = new File(filePath);
        if (!keyFile.exists()) {
            throw new WolfSSLException("Input file does not exist: " +
                filePath);
        }

        fileBytes = WolfSSL.fileToBytes(keyFile);
        if (fileBytes == null) {
            throw new WolfSSLException("Failed to read bytes from file: " +
                filePath);
        }

        signRequest(fileBytes, keyType, format, digestAlg);
    }

    /**
     * Sign certificate request with private key from buffer.
     *
     * @param key Byte array containing private key
     * @param keyType Type of public key algorithm, options are:
     *            WolfSSL.RSAk
     *            WolfSSL.ECDSAk
     * @param format Format of private key file, options are:
     *            WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *            WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     * @param digestAlg Message digest algorithm to use for signature
     *        generation. Options include the following, but native algorithm
     *        must be compiled into wolfSSL to be available:
     *            "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
     *            "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signRequest(byte[] key, int keyType, int format,
        String digestAlg) throws IllegalStateException, WolfSSLException {

        int ret = 0;
        int evpKeyType;

        confirmObjectIsActive();

        if (key == null || key.length == 0) {
            throw new WolfSSLException("Key array is null or empty");
        }

        if (format != WolfSSL.SSL_FILETYPE_ASN1 &&
            format != WolfSSL.SSL_FILETYPE_PEM) {
            throw new WolfSSLException(
                "Invalid key format, must be PEM or DER");
        }

        switch (keyType) {
            case WolfSSL.RSAk:
                evpKeyType = EVP_PKEY_RSA;
                break;
            case WolfSSL.ECDSAk:
                evpKeyType = EVP_PKEY_EC;
                break;
            default:
                throw new WolfSSLException("Unsupported private key type");
        }

        synchronized (x509ReqLock) {
            ret = X509_REQ_sign(this.x509ReqPtr, evpKeyType, key, format,
                    digestAlg);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error signing native X509_REQ " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sign certificate request with private key from PrivateKey object.
     *
     * @param key java.security.PrivateKey object containing private key,
     *        must be of type RSAPrivateKey or ECPrivateKey
     * @param digestAlg Message digest algorithm to use for signature
     *        generation. Options include the following, but native algorithm
     *        must be compiled into wolfSSL to be available:
     *            "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
     *            "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signRequest(PrivateKey key, String digestAlg)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;
        int evpKeyType;
        byte[] encodedKey = null;

        confirmObjectIsActive();

        if (key == null) {
            throw new WolfSSLException("Key object is null");
        }

        if (key instanceof RSAPrivateKey) {
            evpKeyType = EVP_PKEY_RSA;
        }
        else if (key instanceof ECPrivateKey) {
            evpKeyType = EVP_PKEY_EC;
        }
        else {
            throw new WolfSSLException(
                "PrivateKey must be of type RSAPrivateKey or ECPrivateKey");
        }

        /* Get DER encoded key */
        encodedKey = key.getEncoded();
        if (encodedKey == null) {
            throw new WolfSSLException("PrivateKey does not support encoding");
        }

        synchronized (x509ReqLock) {
            ret = X509_REQ_sign(this.x509ReqPtr, evpKeyType, encodedKey,
                WolfSSL.SSL_FILETYPE_ASN1, digestAlg);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error signing native X509_REQ " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Get ASN.1/DER encoding of this CSR, after signRequest() has been called.
     *
     * @return DER encoded array of CSR or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLJNIException if native JNI operation fails
     */
    public byte[] getDer() throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (x509ReqLock) {
            return X509_REQ_get_der(this.x509ReqPtr);
        }
    }

    /**
     * Get PEM encoding of this CSR, after signRequest() has been called.
     *
     * @return PEM encoded array of CSR or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCertRequest has been freed.
     * @throws WolfSSLJNIException if native JNI operation fails
     */
    public byte[] getPem() throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (x509ReqLock) {
            return X509_REQ_get_pem(this.x509ReqPtr);
        }
    }

    @Override
    public String toString() {

        byte[] x509ReqText = null;

        synchronized (stateLock) {
            if (this.active == false) {
                return super.toString();
            }

            synchronized (x509ReqLock) {
                x509ReqText = X509_REQ_print(this.x509ReqPtr);
            }
            if (x509ReqText != null) {
                /* let Java do the modified UTF-8 conversion */
                return new String(x509ReqText, Charset.forName("UTF-8"));
            } else {
                System.out.println("toString: x509ReqTest == null");
            }
        }

        return super.toString();
    }

    /**
     * Frees WolfSSLCertRequest native resources.
     */
    public synchronized void free() {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (x509ReqLock) {
                /* free native resources */
                X509_REQ_free(this.x509ReqPtr);

                /* free Java resources */
                this.active = false;
                this.x509ReqPtr = 0;
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        this.free();
        super.finalize();
    }
}

