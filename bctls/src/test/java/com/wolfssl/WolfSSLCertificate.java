/* WolfSSLCertificate.java
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

import java.io.IOException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.math.BigInteger;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;

/**
 * WolfSSLCertificate class, wraps native wolfSSL WOLFSSL_X509 functionality.
 */
public class WolfSSLCertificate {

    private boolean active = false;
    private long x509Ptr = 0;

    /* Does this WolfSSLCertificate own the internal WOLFSSL_X509 pointer?
     * If not, don't try to free native memory on free(). */
    private boolean weOwnX509Ptr = false;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native WOLFSSL_X509 pointer use */
    private final Object x509Lock = new Object();

    /* cache alt names once retrieved once */
    private Collection<List<?>> altNames = null;

    /* Public key types used for certificate generation, mirrored from
     * native enum in wolfssl/openssl/evp.h */
    private static final int EVP_PKEY_RSA = 16;
    private static final int EVP_PKEY_EC  = 18;

    static native byte[] X509_get_der(long x509);
    static native byte[] X509_get_pem(long x509);
    static native byte[] X509_get_tbs(long x509);
    static native void X509_free(long x509);
    static native int X509_get_serial_number(long x509, byte[] out);
    static native String X509_notBefore(long x509);
    static native String X509_notAfter(long x509);
    static native int X509_version(long x509);
    static native byte[] X509_get_signature(long x509);
    static native String X509_get_signature_type(long x509);
    static native String X509_get_signature_OID(long x509);
    static native byte[] X509_print(long x509);
    static native int X509_get_isCA(long x509);
    static native String X509_get_subject_name(long x509);
    static native String X509_get_issuer_name(long x509);
    static native long X509_get_issuer_name_ptr(long x509);
    static native byte[] X509_get_pubkey(long x509);
    static native String X509_get_pubkey_type(long x509);
    static native int X509_get_pathLength(long x509);
    static native int X509_verify(long x509, byte[] pubKey, int pubKeySz);
    static native boolean[] X509_get_key_usage(long x509);
    static native byte[] X509_get_extension(long x509, String oid);
    static native int X509_is_extension_set(long x509, String oid);
    static native String X509_get_next_altname(long x509);
    static native long X509_load_certificate_buffer(byte[] buf, int format);
    static native long X509_load_certificate_file(String path, int format);
    static native int X509_check_host(long x509, String chk, long flags,
        long peerName);

    /* native functions used for X509v3 certificate generation */
    static native long X509_new();
    static native int X509_set_subject_name(long x509Ptr, long x509NamePtr);
    static native int X509_set_issuer_name(long x509Ptr, long x509NamePtr);
    static native int X509_set_issuer_name_from_der(long x509Ptr, byte[] certDer);
    static native int X509_set_pubkey_native_open(long x509Ptr, int keyType,
        byte[] fileBytes, int format);
    static native int X509_add_altname(long x509Ptr, String name, int type);
    static native int X509_add_ext_via_nconf_nid(long x509Ptr, int nid,
        String extValue, boolean isCritical);
    static native int X509_add_ext_via_set_object_boolean(long x509Ptr,
        int nid, boolean extValue, boolean isCritical);
    static native int X509_set_notBefore(long x509Ptr, long timeSecs);
    static native int X509_set_notAfter(long x509Ptr, long timeSecs);
    static native int X509_set_serialNumber(long x509Ptr, byte[] serialBytes);
    static native int X509_sign(long x509Ptr, int evpKeyType, byte[] keyBytes,
        int format, String digestAlg);

    /**
     * Create new empty WolfSSLCertificate object, for use with X509v3
     * certificate generation.
     *
     * @throws WolfSSLException if native API call fails.
     */
    public WolfSSLCertificate() throws WolfSSLException {

        x509Ptr = X509_new();
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create new WolfSSLCertificate from DER-encoded byte array.
     *
     * @param der ASN.1/DER encoded X.509 certificate
     *
     * @throws WolfSSLException if input is null, input array length is 0,
     *                          or native API call fails.
     */
    public WolfSSLCertificate(byte[] der) throws WolfSSLException {

        if (der == null || der.length == 0) {
            throw new WolfSSLException(
                "Input array must not be null or zero length");
        }

        x509Ptr = X509_load_certificate_buffer(der, WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from byte array in specified format.
     *
     * @param in X.509 certificate byte array in format specified
     * @param format format of certificate, either WolfSSL.SSL_FILETYPE_ASN1
     *               or WolfSSL.SSL_FILETYPE_PEM
     *
     * @throws WolfSSLException if in array is null, input array length is 0,
     *                          format does not match valid options, or
     *                          native API call fails.
     */
    public WolfSSLCertificate(byte[] in, int format) throws WolfSSLException {

        if (in == null || in.length == 0) {
            throw new WolfSSLException(
                "Input array must not be null or zero length");
        }

        if ((format != WolfSSL.SSL_FILETYPE_ASN1) &&
            (format != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException(
                "Input format must be WolfSSL.SSL_FILETYPE_ASN1 or " +
                "WolfSSL.SSL_FILETYPE_PEM");
        }

        x509Ptr = X509_load_certificate_buffer(in, format);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from specified ASN.1/DER X.509 file.
     *
     * @param fileName path to X.509 certificate file in ASN.1/DER format
     *
     * @throws WolfSSLException if fileName is null or native API
     *                          call fails with error.
     */
    public WolfSSLCertificate(String fileName) throws WolfSSLException {

        if (fileName == null) {
            throw new WolfSSLException("Input filename cannot be null");
        }

        x509Ptr = X509_load_certificate_file(fileName,
                                             WolfSSL.SSL_FILETYPE_ASN1);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from specified X.509 file in specified
     * format.
     *
     * @param fileName path to X.509 certificate file
     * @param format format of certificate file, either
     *               WolfSSL.SSL_FILETYPE_ASN1 or
     *               WolfSSL.SSL_FILETYPE_PEM
     *
     * @throws WolfSSLException if input fileName is null, format is not
     *                          valid, or native API call fails.
     */
    public WolfSSLCertificate(String fileName, int format)
            throws WolfSSLException {

        if (fileName == null) {
            throw new WolfSSLException("Input filename cannot be null");
        }

        if ((format != WolfSSL.SSL_FILETYPE_ASN1) &&
            (format != WolfSSL.SSL_FILETYPE_PEM)) {
            throw new WolfSSLException(
                "Input format must be WolfSSL.SSL_FILETYPE_ASN1 or " +
                "WolfSSL.SSL_FILETYPE_PEM");
        }

        x509Ptr = X509_load_certificate_file(fileName, format);
        if (x509Ptr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLCertificate");
        }

        /* x509Ptr has been allocated natively, mark as owned */
        this.weOwnX509Ptr = true;

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Create WolfSSLCertificate from pre existing native pointer.
     *
     * @param x509 pre existing native pointer to WOLFSSL_X509 structure.
     * @param doFree should this WOLFSSL_X509 structure be freed when free()
     *        is called? true to free memory, false to skip free. Free
     *        should be skipped if caller is controlling memory for this
     *        WOLFSSL_X509 struct pointer.
     *
     * @throws WolfSSLException if input pointer is invalid
     */
    public WolfSSLCertificate(long x509, boolean doFree)
        throws WolfSSLException {

        if (x509 == 0) {
            throw new WolfSSLException("Input pointer may not be 0/NULL");
        }
        x509Ptr = x509;

        if (!doFree) {
            /* x509Ptr has NOT been allocated natively, do not mark as owned.
             * Original owner is responsible for freeing. */
            this.weOwnX509Ptr = false;
        }
        else {
            this.weOwnX509Ptr = true;
        }

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Verifies that the current WolfSSLCertificate object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLCertificate object has been freed");
            }
        }
    }

    /**
     * Protected method to be used by objects of this class to get
     * internal WOLFSSL_X509 pointer.
     *
     * @return internal WOLFSSL_X509 pointer value
     * @throws IllegalStateException if object has been freed
     */
    protected long getX509Ptr() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return this.x509Ptr;
        }
    }

    /**
     * Set the Subject Name to be used with this WolfSSLCertificate.
     * Note that the WolfSSLX509Name object should be completely set up
     * before calling this method. This method copies/duplicates the contents
     * of the WOLFSSL_X509_NAME (WolfSSLX509Name) into the native
     * WOLFSSL_X509 structure.
     *
     * @param name Initialized and populated WolfSSLX509 name to be set into
     *        Subject Name of WolfSSLCertificate for cert generation.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void setSubjectName(WolfSSLX509Name name)
        throws IllegalStateException, WolfSSLException {

        int ret;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            /* TODO somehow lock WolfSSLX509Name object while using pointer? */
            ret = X509_set_subject_name(this.x509Ptr,
                    name.getNativeX509NamePtr());
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting subject name " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set the Issuer Name to be used with this WolfSSLCertificate.
     * Note that the WolfSSLX509Name object should be completely set up
     * before calling this method. This method copies/duplicates the contents
     * of the WOLFSSL_X509_NAME (WolfSSLX509Name) into the native
     * WOLFSSL_X509 structure.
     *
     * @param name Initialized and populated WolfSSLX509 name to be set into
     *        Issuer Name of WolfSSLCertificate for cert generation.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void setIssuerName(WolfSSLX509Name name)
        throws IllegalStateException, WolfSSLException {

        int ret;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            /* TODO somehow lock WolfSSLX509Name object while using pointer? */
            ret = X509_set_issuer_name(this.x509Ptr,
                    name.getNativeX509NamePtr());
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting issuer name " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set the Issuer Name to be used with this WolfSSLCertificate.
     * This method copies the issuer name from the existing populated
     * WolfSSLCertificate object, which would commonly be initialized
     * from a CA certificate file or byte array.
     *
     * @param cert Initialized and populated WolfSSLCertificate to be set into
     *        Issuer Name of this WolfSSLCertificate for cert generation.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     */
    public void setIssuerName(WolfSSLCertificate cert)
        throws IllegalStateException, WolfSSLException {

        int ret;
        long x509CertPtr = 0;
        long x509NamePtr = 0;

        confirmObjectIsActive();

        x509NamePtr = X509_get_issuer_name_ptr(cert.getX509Ptr());
        if (x509NamePtr == 0) {
            throw new WolfSSLException("Error getting issuer name from " +
                "WolfSSLCertificate");
        }

        synchronized (x509Lock) {
            /* TODO somehow lock WolfSSLX509Name object while using pointer? */
            ret = X509_set_issuer_name(this.x509Ptr, x509NamePtr);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting issuer name " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set the Issuer Name to be used with this WolfSSLCertificate.
     * This method copies the issuer name from the existing populated
     * X509Certificate object.
     *
     * @param cert Initialized and populated X509Certificate to be used to set
     *        Issuer Name of this WolfSSLCertificate for cert generation.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if native JNI error occurs.
     * @throws CertificateEncodingException if error occurs while parsing
     *         X509Certificate
     */
    public void setIssuerName(X509Certificate cert)
        throws IllegalStateException, WolfSSLException,
               CertificateEncodingException {

        int ret;
        byte[] certDer = null;

        confirmObjectIsActive();

        /* Get DER encoding of certificate */
        certDer = cert.getEncoded();

        synchronized (x509Lock) {
            ret = X509_set_issuer_name_from_der(this.x509Ptr, certDer);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting issuer name " +
                                       "(ret: " + ret + ")");
        }
    }

    /**
     * Set public key for this WolfSSLCertificate, used when generating
     * X509v3 certificates.
     *
     * @param filePath Path to public key file
     * @param keyType Type of public key algorithm, options are:
     *                WolfSSL.RSAk
     *                WolfSSL.ECDSAk
     * @param format Format of public key file, options are:
     *                WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *                WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
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
     * Set public key for this WolfSSLCertificate, used when generating
     * X509v3 certificates.
     *
     * @param key Byte array containing public key
     * @param keyType Type of public key algorithm, options are:
     *                WolfSSL.RSAk
     *                WolfSSL.ECDSAk
     * @param format Format of public key file, options are:
     *                WolfSSL.SSL_FILETYPE_ASN1 (DER formatted)
     *                WolfSSL.SSL_FILETYPE_PEM  (PEM formatted)
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
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

        synchronized (x509Lock) {
            ret = X509_set_pubkey_native_open(this.x509Ptr, evpKeyType,
                    key, format);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting public key into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Set public key for this WolfSSLCertificate, used when generating
     * X509v3 certificates.
     *
     * @param key PublicKey object containing public key to be used when
     *            generating X509v3 certificate.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
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
     * Sets the serial number for this WolfSSLCertificate, used when
     * generating X509v3 certificates.
     *
     * @param serial BigInteger holding serial number for generated cert
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void setSerialNumber(BigInteger serial)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;
        byte[] serialBytes = null;

        confirmObjectIsActive();

        if (serial == null) {
            throw new WolfSSLException("Input BigInteger is null");
        }

        serialBytes = serial.toByteArray();
        if (serialBytes == null || serialBytes.length == 0) {
            throw new WolfSSLException("BigInteger.toByteArray() " +
                "is null or 0 length");
        }

        synchronized (x509Lock) {
            ret = X509_set_serialNumber(this.x509Ptr, serialBytes);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting serial number into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sets the notBefore date for this WolfSSLCertificate, used when
     * generating X509v3 certificates.
     *
     * @param notBefore Date object representing notBefore date/time to set
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void setNotBefore(Date notBefore)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            ret = X509_set_notBefore(this.x509Ptr, notBefore.getTime() / 1000);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting notBefore date into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sets the notAfter date for this WolfSSLCertificate, used when
     * generating X509v3 certificates.
     *
     * @param notAfter Date object representing notAfter date/time to set
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void setNotAfter(Date notAfter)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            ret = X509_set_notAfter(this.x509Ptr, notAfter.getTime() / 1000);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting notAfter date into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Add subject alternative name for this WolfSSLCertificate, used when
     * generating X509v3 certificates.
     *
     * @param name String value of subject alternative name to set
     * @param type Type of subject alt name entry, must be one of:
     *        WolfSSL.ASN_OTHER_TYPE, WolfSSL.ASN_RFC822_TYPE,
     *        WolfSSL.ASN_DNS_TYPE, WolfSSL.ASN_DIR_TYPE, WolfSSL.ASN_URI_TYPE,
     *        WolfSSL.ASN_IP_TYPE
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void addAltName(String name, int type)
        throws IllegalStateException, WolfSSLException {

        int ret = 0;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            ret = X509_add_altname(this.x509Ptr, name, type);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting altName into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Add an extension to a WOLFSSL_X509 given the NID and extension
     * value String.
     *
     * This method supports the following extensions:
     *    - Key Usage (WolfSSL.NID_key_usage)
     *    - Extended Key Usage (WolfSSL.NID_ext_key_usage)
     *    - Subject Alt Name (WolfSSL.NED_subject_alt_name)
     *
     * @param nid NID of extension to add. Must be one of:
     *        WolfSSL.NID_key_usage
     *        WolfSSL.NID_subject_alt_name
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
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
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

        synchronized (x509Lock) {
            ret = X509_add_ext_via_nconf_nid(this.x509Ptr, nid, value,
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
     * Add an extension to a WOLFSSL_X509 given the NID and extension
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
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
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

        synchronized (x509Lock) {
            ret = X509_add_ext_via_set_object_boolean(
                    this.x509Ptr, nid, value, isCritical);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error setting extension into native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sign certificate with private key from file.
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
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws IOException on error opening input file
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signCert(String filePath, int keyType, int format,
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

        signCert(fileBytes, keyType, format, digestAlg);
    }

    /**
     * Sign certificate with private key from buffer.
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
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signCert(byte[] key, int keyType, int format,
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

        synchronized (x509Lock) {
            ret = X509_sign(this.x509Ptr, evpKeyType, key, format, digestAlg);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error signing native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Sign certificate with private key from PrivateKey object.
     *
     * @param key java.security.PrivateKey object containing private key,
     *        must be of type RSAPrivateKey or ECPrivateKey
     * @param digestAlg Message digest algorithm to use for signature
     *        generation. Options include the following, but native algorithm
     *        must be compiled into wolfSSL to be available:
     *            "MD4", "MD5", "SHA1", "SHA224", "SHA256", "SHA384",
     *            "SHA512", "SHA3_224", "SHA3_256", "SHA3_384", "SHA3_512"
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLException if invalid arguments or native JNI error occurs.
     */
    public void signCert(PrivateKey key, String digestAlg)
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

        synchronized (x509Lock) {
            ret = X509_sign(this.x509Ptr, evpKeyType, encodedKey,
                WolfSSL.SSL_FILETYPE_ASN1, digestAlg);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException(
                "Error signing native WOLFSSL_X509 " +
                "(ret: " + ret + ")");
        }
    }

    /**
     * Get ASN.1/DER encoding of this X.509 certificate
     *
     * @return DER encoded array of certificate or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLJNIException if native JNI operation fails
     */
    public byte[] getDer() throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_der(this.x509Ptr);
        }
    }

    /**
     * Get PEM encoding of this X.509 certificate
     *
     * @return PEM encoded array of certificate or null if not available.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws WolfSSLJNIException if native JNI operation fails
     */
    public byte[] getPem() throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_pem(this.x509Ptr);
        }
    }

    /**
     * Get buffer that is To Be Signed (Tbs)
     *
     * @return byte array to be signed
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public byte[] getTbs() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_tbs(this.x509Ptr);
        }
    }

    /**
     * Get X.509 serial number as BigInteger
     *
     * @return serial number as BigInteger, or null if not available
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public BigInteger getSerial() throws IllegalStateException {

        byte[] out = new byte[32];
        int sz;

        confirmObjectIsActive();

        synchronized (x509Lock) {
        sz = X509_get_serial_number(this.x509Ptr, out);
        }
        if (sz <= 0) {
            return null;
        }
        else {
            byte[] serial = Arrays.copyOf(out, sz);
            return new BigInteger(serial);
        }
    }

    /**
     * Get X.509 validity notBefore date
     *
     * @return notBefore date as Date object, or null if not available
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public Date notBefore() throws IllegalStateException {

        String nb;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            nb  = X509_notBefore(this.x509Ptr);
        }
        if (nb != null) {
            SimpleDateFormat format =
                    new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(nb);
            } catch (ParseException ex) {
                /* error case parsing date */
            }
        }

        return null;
    }

    /**
     * Get X.509 validity notAfter date
     *
     * @return notAfter date as Date object, or null if not available
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public Date notAfter() throws IllegalStateException {

        String nb;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            nb = X509_notAfter(this.x509Ptr);
        }
        if (nb != null) {
            SimpleDateFormat format =
                    new SimpleDateFormat("MMM dd HH:mm:ss yyyy zzz");
            try {
                return format.parse(nb);
            } catch (ParseException ex) {
                /* error case parsing date */
            }
        }

        return null;
    }

    /**
     * Get X.509 version
     *
     * @return version of X.509 certificate
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public int getVersion() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_version(this.x509Ptr);
        }
    }

    /**
     * Get signature from X.509 certificate
     *
     * @return byte array with signature from X.509 certificate, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public byte[] getSignature() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_signature(this.x509Ptr);
        }
    }

    /**
     * Get signature type from X.509 certificate
     *
     * @return signature type String, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public String getSignatureType() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_signature_type(this.x509Ptr);
        }
    }

    /**
     * Get X.509 signature algorithm OID
     *
     * @return algorithm OID of signature, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public String getSignatureOID() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_signature_OID(this.x509Ptr);
        }
    }

    /**
     * Get public key from X.509 certificate
     *
     * @return certificate public key, byte array. Or null.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public byte[] getPubkey() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_pubkey(this.x509Ptr);
        }
    }

    /**
     * Get public key type of certificate
     *
     * @return public key type String, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public String getPubkeyType() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_pubkey_type(this.x509Ptr);
        }
    }

    /**
     * Get certificate isCA value
     *
     * @return X.509 isCA value
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public int isCA() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_isCA(this.x509Ptr);
        }
    }

    /**
     * Get certificate path length
     *
     * @return path length, or -1 if not set
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public int getPathLen() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_pathLength(this.x509Ptr);
        }
    }

    /**
     * Get certificate Subject
     *
     * @return X.509 Subject String, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public String getSubject() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_subject_name(this.x509Ptr);
        }
    }

    /**
     * Get certificate Issuer
     *
     * @return X.509 Issuer String, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public String getIssuer() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_issuer_name(this.x509Ptr);
        }
    }

    /**
     * Verify signature in certificate with provided public key
     *
     * @param pubKey public key, ASN.1/DER formatted
     * @param pubKeySz size of public key array, bytes
     *
     * @return true if verified, otherwise false
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public boolean verify(byte[] pubKey, int pubKeySz)
        throws IllegalStateException {

        int ret;

        confirmObjectIsActive();

        synchronized (x509Lock) {
            ret  = X509_verify(this.x509Ptr, pubKey, pubKeySz);
        }
        if (ret == WolfSSL.SSL_SUCCESS) {
            return true;
        }

        return false;
    }

    /**
     * Get array of key usage values set in certificate
     *
     * Array returned will represent the following key usages (true/false):
     *    [0] = KEYUSE_DIGITAL_SIG
     *    [1] = KEYUSE_CONTENT_COMMIT
     *    [2] = KEYUSE_KEY_ENCIPHER
     *    [3] = KEYUSE_DATA_ENCIPHER
     *    [4] = KEYUSE_KEY_AGREE
     *    [5] = KEYUSE_KEY_CERT_SIGN
     *    [6] = KEYUSE_CRL_SIGN
     *    [7] = KEYUSE_ENCIPHER_ONLY
     *    [8] = KEYUSE_DECIPHER_ONLY
     *
     * @return arrray of key usages set for certificate, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public boolean[] getKeyUsage() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_get_key_usage(this.x509Ptr);
        }
    }

    /**
     * Get DER encoded extension value from a specified OID
     *
     * @param oid OID value of extension to retreive value for
     *
     * @return DER encoded extension value, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public byte[] getExtension(String oid) throws IllegalStateException {

        confirmObjectIsActive();

        if (oid == null) {
            return null;
        }

        synchronized (x509Lock) {
            return X509_get_extension(this.x509Ptr, oid);
        }
    }

    /**
     * Poll if certificate extension is set for this certificate
     *
     * @param oid OID value of extension to poll for
     *
     * @return 1 if extension OID is set but not critical,
     *         2 if extension OID is set and is critical,
     *         0 if not set,
     *         otherwise negative value on error
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public int getExtensionSet(String oid) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_is_extension_set(this.x509Ptr, oid);
        }
    }

    /**
     * Checks that given hostname matches this certificate SubjectAltName
     * or CommonName entries.
     *
     * @param hostname Hostname to check certificate against
     *
     * @return WolfSSL.SSL_SUCCESS on successful hostname match,
     *         WolfSSL.SSL_FAILURE on invalid match or error, or
     *         WolfSSL.NOT_COMPILED_IN if native wolfSSL has been compiled
     *         with NO_ASN defined and native API is not available.
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public int checkHost(String hostname) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            return X509_check_host(this.x509Ptr, hostname, 0, 0);
        }
    }

    /**
     * Returns an immutable Collection of subject alternative names from this
     * certificate's SubjectAltName extension.
     *
     * Each collection item is a List containing two objects:
     *     [0] = Integer representing type of name, 0-8 (ex: 2 == dNSName)
     *     [1] = String representing altname entry.
     *
     * Note: this currently returns all altNames as dNSName types, with the
     * second list element being a String.
     *
     * @return immutable Collection of subject alternative names, or null
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     */
    public Collection<List<?>> getSubjectAltNames()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (x509Lock) {
            if (this.altNames != null) {
                /* already gathered, return cached version */
                return this.altNames;
            }

            Collection<List<?>> names = new ArrayList<List<?>>();

            String nextAltName = X509_get_next_altname(this.x509Ptr);
            while (nextAltName != null) {
                Object[] entry = new Object[2];
                entry[0] = 2; // Only return dNSName type for now
                entry[1] = nextAltName;
                List<?> entryList = Arrays.asList(entry);

                names.add(Collections.unmodifiableList(entryList));
                nextAltName = X509_get_next_altname(this.x509Ptr);
            }

            /* cache altNames collection for later use */
            this.altNames = Collections.unmodifiableCollection(names);

            return this.altNames;
        }
    }

    /**
     * Returns X509Certificate object based on this certificate.
     *
     * @return X509Certificate object
     *
     * @throws IllegalStateException if WolfSSLCertificate has been freed.
     * @throws CertificateException on error
     * @throws IOException on error closing ByteArrayInputStream
     * @throws WolfSSLJNIException if native JNI error occurs
     */
    public X509Certificate getX509Certificate()
        throws IllegalStateException, CertificateException, IOException,
               WolfSSLJNIException {

        X509Certificate cert = null;
        InputStream in = null;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        confirmObjectIsActive();

        try {
            in = new ByteArrayInputStream(this.getDer());
            cert = (X509Certificate)cf.generateCertificate(in);
            in.close();

        } catch (Exception e) {
            if (in != null) {
                in.close();
                throw e;
            }
        }

        return cert;
    }

    /**
     * Free native WOLFSSL_X509 structure pointer.
     * This method should be called with caution, so that double free
     * issues do not happen. Calling code should take extra caution to ensure
     * control is maintained around this native pointer and synchronization
     * is used correctly to ensure multiple threads will not free the same
     * pointer simultaneously.
     *
     * This method is needed when WolfSSLSession.getPeerCertificate()
     * is called with wolfSSL versions later than or equal to 5.3.0.
     * See wolfSSL PR 4807.
     *
     * @param x509 pointer to initialized WOLFSSL_X509 structure to be freed
     *        by calling wolfSSL_X509_free() at the JNI level.
     */
    public static void freeX509(long x509) {

        /* No object active check or synchronization needed, since this
         * method is working on a standalone pointer, not related to this
         * object. Method placed here since it relates to common
         * WOLFSSL_X509 / WolfSSLCertificate functionality */
        X509_free(x509);
    }

    @Override
    public String toString() {

        byte[] x509Text;

        synchronized (stateLock) {
            if (this.active == false) {
                return super.toString();
            }

            synchronized (x509Lock) {
                x509Text = X509_print(this.x509Ptr);
            }
            if (x509Text != null) {
                /* let Java do the modified UTF-8 conversion */
                return new String(x509Text, Charset.forName("UTF-8"));
            }
        }

        return super.toString();
    }

    /**
     * Frees WolfSSLCertificate native resources.
     */
    public synchronized void free() {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            /* set this.altNames to null so GC can free */
            this.altNames = null;

            synchronized (x509Lock) {
                /* only free native resources if we own pointer */
                if (this.weOwnX509Ptr == true) {
                    /* free native resources */
                    X509_free(this.x509Ptr);
                }

                /* free Java resources */
                this.active = false;
                this.x509Ptr = 0;
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

