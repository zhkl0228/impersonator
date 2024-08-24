/* WolfSSLContext.java
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

import java.nio.ByteBuffer;
import com.wolfssl.wolfcrypt.EccKey;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLJNIException;

/**
 * Wraps a native WolfSSL context object and contains methods directly related
 * to the SSL/TLS context.
 *
 * @author  wolfSSL
 */
public class WolfSSLContext {

    /* internal native WOLFSSL_CTX pointer */
    private long sslCtxPtr = 0;

    /* user-registerd I/O callbacks, called by internal WolfSSLContext
     * I/O callback. This is done in order to pass references to
     * WolfSSLSession object */
    private WolfSSLIORecvCallback internRecvCb;
    private WolfSSLIOSendCallback internSendCb;

    /* user-registered DTLS cookie generation callback */
    private WolfSSLGenCookieCallback internCookieCb = null;

    /* user-registered MAC/encrypt and decrypt/verify callbacks */
    private WolfSSLMacEncryptCallback internMacEncryptCb = null;
    private WolfSSLDecryptVerifyCallback internDecryptVerifyCb = null;

    /* user-registered ECC sign/verify callbacks */
    private WolfSSLEccSignCallback internEccSignCb = null;
    private WolfSSLEccVerifyCallback internEccVerifyCb = null;

    /* user-registered ECC shared secret callback */
    private WolfSSLEccSharedSecretCallback internEccSharedSecretCb = null;

    /* user-registered RSA sign/verify callbacks */
    private WolfSSLRsaSignCallback internRsaSignCb = null;
    private WolfSSLRsaVerifyCallback internRsaVerifyCb = null;

    /* user-registered RSA enc/dec callbacks */
    private WolfSSLRsaEncCallback internRsaEncCb = null;
    private WolfSSLRsaDecCallback internRsaDecCb = null;

    /* user-registered PSK callbacks */
    private WolfSSLPskClientCallback internPskClientCb = null;
    private WolfSSLPskServerCallback internPskServerCb = null;

    /* is this context active, or has it been freed? */
    private boolean active = false;

    /* lock around active state */
    private final Object stateLock = new Object();

    /* lock around native WOLFSSL_CTX pointer use */
    private final Object ctxLock = new Object();

    /**
     * Creates a new SSL/TLS context for the desired SSL/TLS protocol level.
     *
     * @param method    a pointer (long) to the desired WOLFSSL_METHOD for
     *                  use in the SSL context. This WOLFSSL_METHOD pointer
     *                  is created with one of the protocol-specific methods
     *                  (ex: TLSv1_2_ClientMethod()) matching to the desired
     *                  SSL/TLS/DTLS protocol level.
     *
     * @throws com.wolfssl.WolfSSLException when creation of SSL context fails
     */
    public WolfSSLContext(long method) throws WolfSSLException {
        sslCtxPtr = newContext(method);
        if (sslCtxPtr == 0) {
            throw new WolfSSLException("Failed to create SSL Context");
        }
        this.active = true;
    }

    /* ------------------- private/protected methods -------------------- */

    /**
     * Return native WOLFSSL_CTX pointer.
     *
     * @return pointer to native WOLFSSL_CTX structure for this object
     */
    protected long getContextPtr() {
        synchronized (this.ctxLock) {
            return sslCtxPtr;
        }
    }

    /* used by JNI native recv Cb */
    synchronized WolfSSLIORecvCallback getInternRecvCb() {
        return internRecvCb;
    }

    /* used by JNI native send Cb */
    synchronized WolfSSLIOSendCallback getInternSendCb() {
        return internSendCb;
    }

    /* used by JNI native cookie Cb */
    synchronized WolfSSLGenCookieCallback getInternCookieCb() {
        return internCookieCb;
    }

    /* used by JNI native MAC/encrypt Cb */
    synchronized WolfSSLMacEncryptCallback getInternMacEncryptCb() {
        return internMacEncryptCb;
    }

    /* used by JNI native decrypt/verify Cb */
    synchronized WolfSSLDecryptVerifyCallback getInternDecryptVerifyCb() {
        return internDecryptVerifyCb;
    }

    /* this will be registered with native wolfSSL library */
    private int internalIORecvCallback(WolfSSLSession ssl, byte[] buf, int sz)
    {
        int ret;

        /* call user-registered recv method */
        ret = internRecvCb.receiveCallback(ssl, buf, sz,
                    ssl.getIOReadCtx());

        return ret;
    }

    private int internalIOSendCallback(WolfSSLSession ssl, byte[] buf, int sz)
    {
        int ret;

        /* call user-registered recv method */
        ret = internSendCb.sendCallback(ssl, buf, sz,
                    ssl.getIOWriteCtx());

        return ret;
    }

    private int internalGenCookieCallback(WolfSSLSession ssl, byte[] buf,
            int sz)
    {
        int ret;

        /* call user-registered cookie gen method */
        ret = internCookieCb.genCookieCallback(ssl, buf, sz,
                ssl.getGenCookieCtx());

        return ret;
    }

    private int internalMacEncryptCallback(WolfSSLSession ssl,
            ByteBuffer macOut, byte[] macIn, long macInSz, int macContent,
            int macVerify, ByteBuffer encOut, ByteBuffer encIn, long encSz)
    {
        int ret;

        /* call user-registered MAC/encrypt method */
        ret = internMacEncryptCb.macEncryptCallback(ssl, macOut, macIn,
                macInSz, macContent, macVerify, encOut, encIn, encSz,
                ssl.getMacEncryptCtx());

        return ret;
    }

    private int internalDecryptVerifyCallback(WolfSSLSession ssl,
            ByteBuffer decOut, byte[] decIn, long decSz, int content,
            int verify, long[] padSz)
    {
        int ret;

        /* call user-registered decrypt/verify method */
        ret = internDecryptVerifyCb.decryptVerifyCallback(ssl, decOut,
                decIn, decSz, content, verify, padSz,
                ssl.getDecryptVerifyCtx());

        return ret;
    }

    private int internalEccSignCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, long[] outSz, ByteBuffer keyDer,
            long keySz)
    {
        int ret;

        /* call user-registered ecc sign method */
        ret = internEccSignCb.eccSignCallback(ssl, in, inSz, out, outSz,
                keyDer, keySz, ssl.getEccSignCtx());

        return ret;
    }

    private int internalEccVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer hash, long hashSz, ByteBuffer keyDer,
            long keySz, int[] result)
    {
        int ret;

        /* call user-registered ecc verify method */
        ret = internEccVerifyCb.eccVerifyCallback(ssl, sig, sigSz, hash,
                hashSz, keyDer, keySz, result, ssl.getEccVerifyCtx());

        return ret;
    }

    private int internalEccSharedSecretCallback(WolfSSLSession ssl,
            EccKey otherKey, ByteBuffer pubKeyDer, long[] pubKeyDerSz,
            ByteBuffer out, long[] outSz, int side)
    {
        int ret;

        /* call user-registered ecc shared secret method */
        ret = internEccSharedSecretCb.eccSharedSecretCallback(ssl,
                otherKey, pubKeyDer, pubKeyDerSz, out, outSz, side,
                ssl.getEccSharedSecretCtx());

        return ret;
    }

    private int internalRsaSignCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, int[] outSz, ByteBuffer keyDer,
            long keySz)
    {
        int ret;

        /* call user-registered rsa sign method */
        ret = internRsaSignCb.rsaSignCallback(ssl, in, inSz, out, outSz,
                keyDer, keySz, ssl.getRsaSignCtx());

        return ret;
    }

    private int internalRsaVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
           long sigSz, ByteBuffer out, long outSz, ByteBuffer keyDer,
           long keySz)
    {
        int ret;

        /* call user-registered rsa verify method */
        ret = internRsaVerifyCb.rsaVerifyCallback(ssl, sig, sigSz, out,
                outSz, keyDer, keySz, ssl.getRsaVerifyCtx());

        return ret;
    }

    private int internalRsaEncCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, int[] outSz, ByteBuffer keyDer,
            long keySz)
    {
        int ret;

        /* call user-registered rsa public encrypt method */
        ret = internRsaEncCb.rsaEncCallback(ssl, in, inSz, out, outSz,
                keyDer, keySz, ssl.getRsaEncCtx());

        return ret;
    }

    private int internalRsaDecCallback(WolfSSLSession ssl, ByteBuffer in,
            long inSz, ByteBuffer out, long outSz, ByteBuffer keyDer,
            long keySz)
    {
        int ret;

        /* call user-registered rsa private decrypt method */
        ret = internRsaDecCb.rsaDecCallback(ssl, in, inSz, out, outSz, keyDer,
                keySz, ssl.getRsaDecCtx());

        return ret;
    }

    private long internalPskClientCallback(WolfSSLSession ssl, String hint,
            StringBuffer identity, long idMaxLen, byte[] key,
            long keyMaxLen)
    {
        long ret;

        /* call user-registered PSK client callback method */
        ret = internPskClientCb.pskClientCallback(ssl, hint, identity,
                idMaxLen, key, keyMaxLen);

        return ret;
    }

    private long internalPskServerCallback(WolfSSLSession ssl,
            String identity, byte[] key, long keyMaxLen)
    {
        long ret;

        /* call user-registered PSK server callback method */
        ret = internPskServerCb.pskServerCallback(ssl, identity,
                key, keyMaxLen);

        return ret;
    }

    /**
     * Verifies that the current WolfSSLContext object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private synchronized void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLContext object has been freed");
            }
        }
    }

    /* ------------------ native method declarations -------------------- */

    private native long newContext(long method);
    private native int setTmpDH(long ctx, byte[] p, int pSz, byte[] g, int gSz);
    private native int setTmpDHFile(long ctx, String fname, int format);
    private native int useCertificateFile(long ctx, String file, int format);
    private native int usePrivateKeyFile(long ctx, String file, int format);
    private native int loadVerifyLocations(long ctx, String file, String path);
    private native int useCertificateChainFile(long ctx, String file);
    private native void freeContext(long ctx);
    private native void setVerify(long ctx, int mode, WolfSSLVerifyCallback vc);
    private native long setOptions(long ctx, long op);
    private native long getOptions(long ctx);
    private native int memsaveCertCache(long ctx, byte[] mem, int sz,
            int[] used);
    private native int memrestoreCertCache(long ctx, byte[] mem, int sz);
    private native int getCertCacheMemsize(long ctx);
    private native long setCacheSize(long ctx, long sz);
    private native long getCacheSize(long ctx);
    private native int setCipherList(long ctx, String list);
    private native int loadVerifyBuffer(long ctx, byte[] in, long sz,
            int format);
    private native int useCertificateBuffer(long ctx, byte[] in, long sz,
            int format);
    private native int usePrivateKeyBuffer(long ctx, byte[] in, long sz,
            int format);
    private native int useCertificateChainBuffer(long ctx, byte[] in, long sz);
    private native int useCertificateChainBufferFormat(long ctx, byte[] in,
            long sz, int format);
    private native int setGroupMessages(long ctx);
    private native void setIORecv(long ctx);
    private native void setIOSend(long ctx);
    private native void setGenCookie(long ctx);
    private native int enableCRL(long ctx, int options);
    private native int disableCRL(long ctx);
    private native int loadCRL(long ctx, String path, int type, int monitor);
    private native int setCRLCb(long ctx, WolfSSLMissingCRLCallback cb);
    private native int enableOCSP(long ctx, long options);
    private native int disableOCSP(long ctx);
    private native int setOCSPOverrideUrl(long ctx, String url);
    private native void setMacEncryptCb(long ctx);
    private native void setDecryptVerifyCb(long ctx);
    private native void setEccSignCb(long ctx);
    private native void setEccVerifyCb(long ctx);
    private native void setEccSharedSecretCb(long ctx);
    private native void setRsaSignCb(long ctx);
    private native void setRsaVerifyCb(long ctx);
    private native void setRsaEncCb(long ctx);
    private native void setRsaDecCb(long ctx);
    private native void setPskClientCb(long ctx);
    private native void setPskServerCb(long ctx);
    private native int usePskIdentityHint(long ssl, String hint);
    private native int useSupportedCurve(long ctx, int name);
    private native int setGroups(long ctx, int[] groups);
    private native int set1SigAlgsList(long ctx, String list);
    private native int useSecureRenegotiation(long ctx);
    private native int setMinDhKeySz(long ctx, int keySzBits);
    private native int setMinRsaKeySz(long ctx, int keySzBits);
    private native int setMinEccKeySz(long ctx, int keySzBits);
    private native int setDevId(long ctx, int devId);
    private native void flushSessions(long ctx, int tm);

    /* ------------------- context-specific methods --------------------- */

    /**
     * Loads a certificate file into the SSL context.
     * This file is provided by the <b>file</b> parameter. The <b>format</b>
     * paramenter specifies the format type of the file - either
     * <b>SSL_FILETYPE_ASN1</b> or <b>SSL_FILETYPE_PEM</b>. Please see the
     * wolfSSL examples for proper usage.
     *
     * @param file      a file containing the certificate to be loaded into
     *                  the wolfSSL SSL context.
     * @param format    format of the certificates pointed to by <code>file
     *                  </code>. Possible options are <b>SSL_FILETYPE_ASN1</b>,
     *                  for DER-encoded certificates, or <b>SSL_FILETYPE_PEM
     *                  </b> for PEM-encoded certificates.
     * @return          <code>SSL_SUCCESS</code> upon success, otherwise
     *                  <code>SSL_FAILURE</code>. Possible failure causes
     *                  may be that the file is in the wrong format, the
     *                  format argument was given incorrectly, the file
     *                  doesn't exist, can't be read, or is corrupted,
     *                  an out of memory condition occurs, or the Base16
     *                  decoding fails on the file.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input file is null
     * @see    WolfSSLSession#useCertificateFile(String, int)
     */
    public int useCertificateFile(String file, int format)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useCertificateFile(getContextPtr(), file, format);
        }
    }

    /**
     * Loads a private key file into the SSL context.
     * This file is provided by the <b>file</b> parameter. The <b>format</b>
     * paramenter specifies the format type of the file - either
     * <b>SSL_FILETYPE_ASN1</b> or <b>SSL_FILETYPE_PEM</b>. Please see the
     * wolfSSL examples for proper usage.
     *
     * @param file      a file containing the private key to be loaded into
     *                  the wolfSSL SSL context.
     * @param format    format of the private key pointed to by <code>file
     *                  </code>. Possible options are <b>SSL_FILETYPE_ASN1</b>,
     *                  for a DER-encoded key, or <b>SSL_FILETYPE_PEM
     *                  </b> for a PEM-encoded key.
     * @return          <code>SSL_SUCCESS</code> upon success, otherwise
     *                  <code>SSL_FAILURE</code>. Possible failure causes
     *                  may be that the file is in the wrong format, the
     *                  format argument was given incorrectly, the file
     *                  doesn't exist, can't be read, or is corrupted,
     *                  an out of memory condition occurs, the Base16
     *                  decoding fails on the file, or the key file is
     *                  encrypted but no password is provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input file is null
     * @see    WolfSSLSession#usePrivateKeyFile(String, int)
     */
    public int usePrivateKeyFile(String file, int format)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return usePrivateKeyFile(getContextPtr(), file, format);
        }
    }

    /**
     * Loads PEM-formatted CA certificates into the SSL context.
     * These certificates will be treated as trusted root certificates and
     * used to verify certs received from peers during the SSL handshake.
     * <p>
     * The root certificate provided by the <b>file</b> paramter may be a
     * single certificate or a file containing multiple certificates. If
     * multiple CA certs are included in the same file, wolfSSL will load them
     * in the same order which they are presented in the file. The <b>path</b>
     * parameter is a directory path which contains certificates of trusted
     * root CAs. If the value of <b>file</b> is not NULL, <b>path</b> may be
     * specified as <code>null</code> if not needed. If <b>path</b> is
     * specified, and <code>NO_WOLFSSL_DIR</code> is defined when building the
     * library, wolfSSL will load all CA certificates located in the given
     * directory.
     *
     * @param file  path to the file containing PEM-formatted CA certificates
     * @param path  path to directory containing PEM-formatted CA certificates
     *              to load
     * @return      <code>SSL_SUCCESS</code> on success. Otherwise<br>
     *              <code>SSL_FAILURE</code> if <b>ctx</b> is null, or if
     *              both <b>file</b> and <b>path</b> are null.<br>
     *              <code>SSL_BAD_FILETYPE</code> if the file is in the
     *              wrong format.<br>
     *              <code>SSL_BAD_FILE</code> if the file doesn't exist, can't
     *              be read, or is corrupted.<br>
     *              <code>MEMORY_E</code> if an out of memory condition
     *              occurs.<br>
     *              <code>ASN_INPUT_E</code> if Base16 decoding fails on the
     *              file.<br>
     *              <code>BUFFER_E</code> if a chain buffer is bigger than the
     *              recieving buffer.<br>
     *              <code>BAD_PATH_ERROR</code> if the native opendir()
     *              function call fails when trying to open <b>path</b>.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input file and path are null
     * @see    #useCertificateFile(String, int)
     * @see    #usePrivateKeyFile(String, int)
     * @see    #useCertificateChainFile(String)
     * @see    WolfSSLSession#useCertificateFile(String, int)
     * @see    WolfSSLSession#usePrivateKeyFile(String, int)
     * @see    WolfSSLSession#useCertificateChainFile(String)
     */
    public int loadVerifyLocations(String file, String path)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return loadVerifyLocations(getContextPtr(), file, path);
        }
    }

    /**
     * Loads a chain of certificates into the SSL context.
     * The file containing the certificate chain is provided by the <b>file</b>
     * parameter and must contain PEM-formatted certificates. This function
     * will process up to <code>MAX_CHAIN_DEPTH</code> (default = 9, defined
     * in internal.h) certificates, plus the subject cert.
     *
     * @param file  path to the file containing the chain of certificates
     *              to be loaded into the wolfSSL SSL context. Certificates
     *              must be in PEM format.
     * @return      <code>SSL_SUCCESS</code> on success, otherwise <code>
     *              SSL_FAILURE</code>. If the function call fails, possible
     *              causes might include: the file is in the wrong format,
     *              the file doesn't exist, can't be read, or is corrupted, or
     *              an out of memory condition occurs.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input file is null
     * @see    #useCertificateFile(String, int)
     * @see    WolfSSLSession#useCertificateFile(String, int)
     */
    public int useCertificateChainFile(String file)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useCertificateChainFile(getContextPtr(), file);
        }
    }


    /**
     * Sets the verification method for remote peers and also allows a
     * verify callback to be registered with the SSL session.
     * If no verify callback is desired, null can be used for <code>
     * callback</code>.
     * <p>
     * The verification <b>mode</b> of peer certificates is a logically
     * OR'd list of flags. The possible flag values include:
     * <p>
     * <code>SSL_VERIFY_NONE</code><br>
     * <b>Client mode:</b> the client will not verify the certificate
     * received from teh server and the handshake will continue as normal.<br>
     * <b>Server mode:</b> the server will not send a certificate request to
     * the client. As such, client verification will not be enabled.
     * <p>
     * <code>SSL_VERIFY_PEER</code><br>
     * <b>Client mode:</b> the client will verify the certificate received
     * from the server during the handshake. This is turned on by default in
     * wolfSSL, therefore, using this option has no effect.<br>
     * <b>Server mode:</b> the server will send a certificate request to the
     * client and verify the client certificate received.
     * <p>
     * <code>SSL_VERIFY_FAIL_IF_NO_PEER_CERT</code><br>
     * <b>Client mode:</b> no effect when used on the client side.<br>
     * <b>Server mode:</b> the verification will fail on the server side if
     * the client fails to send a certificate when requested to do so (when
     * using SSL_VERIFY_PEER on the SSL server).
     *
     * @param mode      verification type
     * @param callback  custom verification callback to register with the SSL
     *                  session. If no callback is desired, <code>null</code>
     *                  may be used.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public void setVerify(int mode, WolfSSLVerifyCallback callback)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            setVerify(getContextPtr(), mode, callback);
        }
    }

    /**
     * Sets the options to use for the WOLFSSL structure.
     * Example options are WolfSSL.SSL_OP_NO_SSLv3
     *
     *
     * @param op      bit mask of options to set
     * @return returns the revised options bit mask on success
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long setOptions(long op)
            throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setOptions(getContextPtr(), op);
        }
    }

        /**
     * Gets the options to use for the WOLFSSL structure.
     * Example options are WolfSSL.SSL_OP_NO_SSLv3
     *
     *
     * @return returns options bit mask on success
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long getOptions()
            throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return getOptions(getContextPtr());
        }
    }

    /**
     * Frees an allocated SSL context.
     * This method decrements the CTX reference count and only frees the
     * context when the reference count has reached zero.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see         WolfSSLSession#freeSSL()
     */
    public synchronized void free() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (ctxLock) {
                /* free native resources */
                freeContext(this.sslCtxPtr);

                /* free Java resources */
                this.active = false;
                this.sslCtxPtr = 0;
            }
        }
    }

    /**
     * Persists the certificate cache to memory.
     * Use this method to store the current certificate cache to a memory
     * buffer.
     *
     * @param mem   the buffer to store the certificate cache in
     * @param sz    the size of the output buffer, <b>mem</b>
     * @param used  output parameter, the size of the cert cache in bytes is
     *              returned in the first element of this array.
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>SSL_FAILURE</code></b> on general failure,
     *              <b><code>BAD_FUNC_ARG</code></b> if null or negative
     *              parameters are passed in,
     *              <b><code>BAD_MUTEX_ERROR</code></b> if the CA mutex lock
     *              fails, <b><code>BUFFER_E</code></b> if the output buffer
     *              is too small.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSL#memsaveSessionCache(byte[], int)
     * @see    WolfSSL#memrestoreSessionCache(byte[], int)
     * @see    WolfSSL#getSessionCacheMemsize()
     * @see    #memsaveCertCache(byte[], int, int[])
     * @see    #memrestoreCertCache(byte[], int)
     * @see    #getCertCacheMemsize()
     */
    public int memsaveCertCache(byte[] mem, int sz, int[] used)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return memsaveCertCache(getContextPtr(), mem, sz, used);
        }
    }

    /**
     * Restores the certificate cache from memory.
     * This method restores the certificate cache from a saved memory buffer.
     *
     * @param mem   memory buffer containing the stored certificate cache
     *              to restore
     * @param sz    size of the input memory buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> upon success,
     *              <b><code>SSL_FAILURE</code></b> upon general failure,
     *              <b><code>BAD_FUNC_ARG</code></b> if null or negative
     *              parameters are passed in,
     *              <b><code>BUFFER_E</code></b> if the certificate cache
     *              memory buffer is too small,
     *              <b><code>CACHE_MATCH_ERROR</code></b> if the cert cache
     *              memory header match failed,
     *              <b><code>BAD_MUTEX_ERROR</code></b> if the CA mutex lock
     *              failed.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSL#memsaveSessionCache(byte[], int)
     * @see    WolfSSL#memrestoreSessionCache(byte[], int)
     * @see    WolfSSL#getSessionCacheMemsize()
     * @see    #memsaveCertCache(byte[], int, int[])
     * @see    #getCertCacheMemsize()
     */
    public int memrestoreCertCache(byte[] mem, int sz)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return memrestoreCertCache(getContextPtr(), mem, sz);
        }
    }

    /**
     * Gets how big the certificate cache save buffer needs to be.
     * Use this method to get how big the output buffer needs to be in which
     * to save the current certifiate cache to memory.
     *
     * @return size, in bytes, of how large the output buffer should be
     *         to store the certificate cache into memory.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSL#memsaveSessionCache(byte[], int)
     * @see    WolfSSL#memrestoreSessionCache(byte[], int)
     * @see    WolfSSL#getSessionCacheMemsize()
     * @see    #memsaveCertCache(byte[], int, int[])
     * @see    #memrestoreCertCache(byte[], int)
     */
    public int getCertCacheMemsize()
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return getCertCacheMemsize(getContextPtr());
        }
    }

    /**
     * Cache size is set at compile time.This function returns the current cache
     * size which has been set at compile time.
     * An example of macros to set cache size are HUGE_SESSION_CACHE and
     * SMALL_SESSION_CACHE.
     *
     * @param sz unused size to set cache as
     * @return size of compile time cache.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long setCacheSize(long sz) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setCacheSize(getContextPtr(), sz);
        }
    }

    /**
     * Gets the cache size is set at compile time.
     * This function returns the current cache size which has been set at compile
     * time.
     *
     * @return size of compile time cache.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public long getCacheSize() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return getCacheSize(getContextPtr());
        }
    }

    /**
     * Sets the cipher suite list for a given SSL context.
     * This cipher suite list becomes the default list for any new SSL
     * sessions created using this context. The ciphers in the list should
     * be sorted in order of preference from highest to lowest. Each call
     * to <code>ctxSetCipherList()</code> resets the cipher suite list for
     * the specific SSL context to the provided list each time time the
     * method is called.
     * <p>
     * The cipher suite list, <b>list</b>, is a null-terminated text String,
     * and colon-delimited list. For example, one possible list may be:
     * <p>
     * <code>"DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:AES256-SHA256"</code>
     * <p>
     * Valid cipher values are the full name values from the cipher_names[]
     * array in the native wolfSSL src/internal.c:
     *
     * @param list      null-terminated text string and colon-delimited list
     *                  of cipher suites to use with the specified SSL
     *                  context.
     * @return          <code>SSL_SUCCESS</code> upon success. <code>
     *                  SSL_FAILURE</code> upon failure.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input list is null
     * @see    WolfSSLSession#setCipherList(String)
     */
    public int setCipherList(String list)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setCipherList(getContextPtr(), list);
        }
    }

    /**
     * Sets up the group parameters to be used if the server negotiates
     * a cipher suite that uses DHE.
     *
     * @param p     Diffie-Hellman prime number parameter
     * @param pSz   size of <code>p</code>
     * @param g     Diffie-Hellman "generator" parameter
     * @param gSz   size of <code>g</code>
     * @return      <code>SSL_SUCCESS</code> on success. <code>MEMORY_E
     *              </code> if a memory error was encountered. <code>
     *              SIDE_ERROR</code> if this function is called on an
     *              SSL client instead of an SSL server.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public int setTmpDH(byte[] p, int pSz, byte[] g, int gSz)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setTmpDH(getContextPtr(), p, pSz, g, gSz);
        }
    }

    /**
     * Sets up the group parameters from the specified file to be used if the
     * server negotiates a cipher suite that uses DHE.
     *
     * @param fname     path to Diffie-Hellman parameter file
     * @param format    format of DH parameter file, either
     *                  <code>SSL_FILETYPE_ASN1</code> or <code>
     *                  SSL_FILETYPE_PEM</code>.
     * @return          <code>SSL_SUCCESS</code> on success. <code>MEMORY_E
     *                  </code> if a memory error was encountered. <code>
     *                  SIDE_ERROR</code> if this function is called on an
     *                  SSL client instead of an SSL server, <code>
     *                  SSL_BAD_FILETYPE</code> if the specified format is
     *                  incorrect, <code>SSL_BAD_FILE</code> if there is a
     *                  problem with the input file.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setTmpDH(byte[], int, byte[], int)
     */
    public int setTmpDHFile(String fname, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setTmpDHFile(getContextPtr(), fname, format);
        }
    }

    /**
     * Loads a CA certificate buffer into the SSL context.
     * This method behaves like the non-buffered version, only differing in its
     * ability to be called with a buffer as input instead of a file. The
     * buffer is provided by the <b>in</b> parameter of size <b>sz</b>.
     * <b>format</b> specifies the format type of the buffer, either
     * <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>. More than one
     * CA certificate may be loaded per buffer as long as the format is in
     * PEM format.
     *
     * @param in        input buffer containing CA certificate to load
     * @param sz        size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>BUFFER_E</code></b> will be returned if a
     *                  chain buffer is bigger than the receiving buffer, and
     *                  <b><code>BAD_FUNC_ARG</code></b> will be returned
     *                  if invalid arguments are provided.
     *
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #loadVerifyLocations(String, String)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    #useCertificateChainBuffer(byte[], long)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int loadVerifyBuffer(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return loadVerifyBuffer(getContextPtr(), in, sz, format);
        }
    }

    /**
     * Loads a certificate buffer into the SSL context.
     * This method behaves like the non-buffered version, only differing in its
     * ability to be called with a buffer as input instea of a file.
     *
     * @param in        input buffer containing the certificate to load
     * @param sz        size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file, <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input arguments
     *                  are provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #loadVerifyBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    #useCertificateChainBuffer(byte[], long)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int useCertificateBuffer(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useCertificateBuffer(getContextPtr(), in, sz, format);
        }
    }

    /**
     * Loads a private key buffer into the SSL context.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input rather than a file.
     *
     * @param in        the input buffer containing the private key to be
     *                  loaded
     * @param sz        the size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>NO_PASSWORD</code></b> if the key file is
     *                  encrypted but no password is provided, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input arguments
     *                  are provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #loadVerifyBuffer(byte[], long, int)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #useCertificateChainBuffer(byte[], long)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int usePrivateKeyBuffer(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return usePrivateKeyBuffer(getContextPtr(), in, sz, format);
        }
    }

    /**
     * Loads a certificate chain buffer into the SSL context.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input instead of a file.
     * The buffer must be in PEM format and start with the subject's
     * certificate, ending with the root certificate.
     *
     * @param in        the input buffer containing the PEM-formatted
     *                  certificate chain to be loaded.
     * @param sz        the size of the input buffer, <b>in</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>BUFFER_E</code></b> if a chain buffer is
     *                  bigger than the receiving buffer, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input arguments
     *                  are provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #loadVerifyBuffer(byte[], long, int)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int useCertificateChainBuffer(byte[] in, long sz)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useCertificateChainBuffer(getContextPtr(), in, sz);
        }
    }

    /**
     * Loads a certificate chain buffer into the SSL context in specific format.
     * This method behaves like the non-buffered version, only differing
     * in its ability to be called with a buffer as input instead of a file.
     * This function is similar to useCertificateChainBuffer(), but allows
     * the input format to be specified. The format must be either DER or PEM,
     * and start with the subject's certificate, ending with the root
     * certificate.
     *
     * @param in        the input buffer containing the PEM or DER formatted
     *                  certificate chain to be loaded.
     * @param sz        the size of the input buffer, <b>in</b>
     * @param format    format of the certificate buffer being loaded - either
     *                  <b>SSL_FILETYPE_PEM</b> or <b>SSL_FILETYPE_ASN1</b>
     * @return          <b><code>SSL_SUCCESS</code></b> upon success,
     *                  <b><code>SSL_FAILURE</code></b> upon general failure,
     *                  <b><code>SSL_BAD_FILETYPE</code></b> if the file is
     *                  in the wrong format, <b><code>SSL_BAD_FILE</code></b>
     *                  if the file doesn't exist, can't be read, or is
     *                  corrupted. <b><code>MEMORY_E</code></b> if an out of
     *                  memory condition occurs, <b><code>ASN_INPUT_E</code></b>
     *                  if Base16 decoding fails on the file,
     *                  <b><code>BUFFER_E</code></b> if a chain buffer is
     *                  bigger than the receiving buffer, and <b><code>
     *                  BAD_FUNC_ARG</code></b> if invalid input arguments
     *                  are provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #loadVerifyBuffer(byte[], long, int)
     * @see    #useCertificateBuffer(byte[], long, int)
     * @see    #usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateBuffer(byte[], long, int)
     * @see    WolfSSLSession#usePrivateKeyBuffer(byte[], long, int)
     * @see    WolfSSLSession#useCertificateChainBuffer(byte[], long)
     */
    public int useCertificateChainBufferFormat(byte[] in, long sz, int format)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useCertificateChainBufferFormat(
                        getContextPtr(), in, sz, format);
        }
    }

    /**
     * Turns on grouping of the handshake messages where possible using the
     * SSL context.
     *
     * @return          <b><code>SSL_SUCCESS</code></b> upon success. <b><code>
     *                  BAD_FUNC_ARG</code></b> if the input context is null.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLSession#setGroupMessages()
     */
    public int setGroupMessages() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setGroupMessages(getContextPtr());
        }
    }

    /**
     * Registers a receive callback for wolfSSL to get input data.
     * By default, wolfSSL uses EmbedReceive() in src/io.c as the callback.
     * This uses the system's TCP recv() function. The user can register a
     * function to get input from memory, some other network module, or from
     * anywhere. Please see the EmbedReceive() function in src/io.c as a
     * guide for how the function should work and for error codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_READ</b> should be returned for
     * non-blocking receive when no data is ready.
     *
     * @param callback  method to be registered as the receive callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLIORecvCallback#receiveCallback(WolfSSLSession,
     *                  byte[], int, long).
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIOSend(WolfSSLIOSendCallback)
     */
    public synchronized void setIORecv(WolfSSLIORecvCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set user I/O recv */
        internRecvCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setIORecv(getContextPtr());
        }
    }

    /**
     * Registers a send callback for wolfSSL to write output data.
     * By default, wolfSSL uses EmbedSend() in src/io.c as the callback,
     * which uses the system's TCP send() function. The user can register
     * a function to send output to memory, some other network module, or
     * to anywhere. Please see the EmbedSend() function in src/io.c as a
     * guide for how the function should work and for error codes.
     * <p>
     * In particular, <b>IO_ERR_WANT_WRITE</b> should be returned for
     * non-blocking send when the action cannot be taken yet.
     *
     * @param callback  method to be registered as the send callback for
     *                  the wolfSSL context. The signature of this function
     *                  must follow that as shown in
     *                  WolfSSLIOSendCallback#sendCallback(WolfSSLSession,
     *                  byte[], int, Object).
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setIORecv(WolfSSLIORecvCallback)
     */
    public synchronized void setIOSend(WolfSSLIOSendCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set user I/O send */
        internSendCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setIOSend(getContextPtr());
        }
    }

    /**
     * Registers a DTLS cookie generation callback.
     * By default, wolfSSL uses EmbedGenerateCookie() in src/io.c as the
     * callback, which does a SHA hash of the peer's address and port.
     * This method can be used to register a custom cookie generation
     * callback, which is needed when the application is using custom I/O
     * callbacks.
     * <p>
     * The cookie generation callback should return the size of the resulting
     * cookie (normally, the size of the SHA hash generated), or
     * WolfSSL.GEN_COOKIE_E upon error.
     *
     * @param callback  method to be registered as the cookie generation
     *                  callback for the wolfSSL context. The signature
     *                  of this function must follow that as shown in
     *                  WolfSSLGenCookieCallback#genCookieCallback(
     *                  WolfSSLSession, byte[], int, Object).
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     */
    public synchronized void setGenCookie(WolfSSLGenCookieCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set DTLS cookie generation callback */
        internCookieCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setGenCookie(getContextPtr());
        }
    }

    /**
     * Turns on Certificate Revocation List (CRL) checking when
     * verifying certificates for the specified Context.
     * By default, CRL checking is off. <b>options</b> include
     * WOLFSSL_CRL_CHECKALL which performs CRL checking on each certificate
     * in the chain versus the leaf certificate only (which is default).
     *
     * @param options  options to use when enabling CRL
     * @return         <code>SSL_SUCCESS</code> upon success. <code>
     *                 NOT_COMPILED_IN</code> if wolfSSL was not compiled
     *                 with CRL enabled. <code>MEMORY_E</code> if an out
     *                 of memory condition occurs. <code>BAD_FUNC_ARG</code>
     *                 if a pointer is not provided, and <code>
     *                 SSL_FAILURE</code> if the CRL context cannot be
     *                 initialized properly.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLSession#enableCRL(int)
     * @see    WolfSSLSession#disableCRL()
     * @see    WolfSSLSession#loadCRL(String, int, int)
     * @see    WolfSSLSession#setCRLCb(WolfSSLMissingCRLCallback)
     * @see    #disableCRL()
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int enableCRL(int options) throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return enableCRL(getContextPtr(), options);
        }
    }

    /**
     * Turns off Certificate Revocation List (CRL) checking for the
     * specified Context.
     * By default, CRL checking is off. This function can be used to
     * temporarily or permanently disable CRL checking for a given SSL
     * session object that previously had CRL checking enabled.
     *
     * @return <code>SSL_SUCCESS</code> on success, <code>
     *         BAD_FUNC_ARG</code> if pointer is not provided.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLSession#enableCRL(int)
     * @see    WolfSSLSession#disableCRL()
     * @see    WolfSSLSession#loadCRL(String, int, int)
     * @see    WolfSSLSession#setCRLCb(WolfSSLMissingCRLCallback)
     * @see    #enableCRL(int)
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int disableCRL() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return disableCRL(getContextPtr());
        }
    }

    /**
     * Loads CRL files into wolfSSL from the specified path, using the
     * specified Context.
     * This method loads a list of CRL files into wolfSSL. The files can be
     * in either PEM or DER format, as specified by the <b>type</b>
     * parameter.
     *
     * @param path     path to directory containing CRL files
     * @param type     type of files in <b>path</b>, either <code>
     *                 SSL_FILETYPE_PEM</code> or <code>SSL_FILETYPE_ASN1
     *                 </code>.
     * @param monitor  OR'd list of flags to indicate if wolfSSL should
     *                 monitor the provided CRL directory for changes.
     *                 Flag values include <code>WOLFSSL_CRL_MONITOR</code>
     *                 to indicate that the directory should be monitored
     *                 and <code>WOLFSSL_CRL_START_MON</code> to start the
     *                 monitor.
     * @return         <b><code>SSL_SUCCESS</code></b> upon success<br>
     *                 <b><code>SSL_FATAL_ERROR</code></b> if enabling the
     *                 internal CertManager fails<br>
     *                 <b><code>BAD_FUNC_ARG</code></b> if the SSL pointer
     *                 is null<br>
     *                 <b><code>BAD_PATH_ERROR</code></b> if there is an
     *                 error opening the provided directory<br>
     *                 <b><code>MEMORY_E</code></b> if a memory error
     *                 occurred<br>
     *                 <b><code>MONITOR_RUNNING_E</code></b> if the CRL
     *                 monitor is already running<br>
     *                 <b><code>THREAD_CREATE_E</code></b> if there was an
     *                 error when creating the CRL monitoring thread.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLSession#enableCRL(int)
     * @see    WolfSSLSession#disableCRL()
     * @see    WolfSSLSession#loadCRL(String, int, int)
     * @see    WolfSSLSession#setCRLCb(WolfSSLMissingCRLCallback)
     * @see    #enableCRL(int)
     * @see    #disableCRL()
     * @see    #setCRLCb(WolfSSLMissingCRLCallback)
     */
    public int loadCRL(String path, int type, int monitor)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return loadCRL(getContextPtr(), path, type, monitor);
        }
    }

    /**
     * Registers CRL callback to be called when CRL lookup fails, using
     * specified Context.
     *
     * @param cb callback to be registered with SSL context, called
     *           when CRL lookup fails.
     * @return   <b><code>SSL_SUCCESS</code></b> upon success,
     *           <b><code>BAD_FUNC_ARG</code></b> if SSL pointer is null.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#enableCRL(int)
     * @see    WolfSSLSession#disableCRL()
     * @see    WolfSSLSession#loadCRL(String, int, int)
     * @see    WolfSSLSession#setCRLCb(WolfSSLMissingCRLCallback)
     * @see    #enableCRL(int)
     * @see    #disableCRL()
     */
    public int setCRLCb(WolfSSLMissingCRLCallback cb)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setCRLCb(getContextPtr(), cb);
        }
    }

    /**
     * Enable OCSP functionality for this context, set options.
     * The value of <b>options</b> is formed by OR'ing one or more of the
     * following options:<br>
     * <b>WOLFSSL_OCSP_NO_NONCE</b> - disable sending OCSP nonce<br>
     * <b>WOLFSSL_OCSP_URL_OVERRIDE</b> - use the override URL instead of the
     * URL in certificates<br>
     * This function only sets the OCSP options when wolfSSL has been
     * compiled with OCSP support (--enable-ocsp, #define HAVE_OCSP).
     *
     * @param options  value used to set the OCSP options
     * @return         <b><code>SSL_SUCCESS</code></b> upon success,
     *                 <b><code>SSL_FAILURE</code></b> upon failure,
     *                 <b><code>BAD_FUNC_ARG</code></b> if context is null,
     *                 <b><code>MEMORY_E</code></b> upon memory error,
     *                 <b><code>NOT_COMPILED_IN</code></b> when this function
     *                 has been called, but OCSP support was not enabled when
     *                 wolfSSL was compiled.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #disableOCSP
     * @see    #setOCSPOverrideUrl(String)
     */
    public int enableOCSP(long options)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return enableOCSP(getContextPtr(), options);
        }
    }

    /**
     * Disable OCSP for this context.
     * @return  <b><code>SSL_SUCCESS</code></b> upon success,
     *          <b><code>BAD_FUNC_ARG</code></b> if context is null,
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    #enableOCSP(long)
     * @see    #setOCSPOverrideUrl(String)
     */
    public int disableOCSP() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return disableOCSP(getContextPtr());
        }
    }

    /**
     * Manually sets the URL for OCSP to use.
     * By default, OCSP will use the URL found in the individual certificate
     * unless the WOLFSSL_OCSP_URL_OVERRIDE option is set using the
     * setOCSPOptions() method.
     *
     * @param url the OCSP override URL for wolfSSL to use
     * @return    <b><code>SSL_SUCCESS</code></b> upon success,
     *            <b><code>SSL_FAILURE</code></b> upon failure,
     *            <b><code>NOT_COMPILED_IN</code></b> when this function has
     *            been called, but OCSP support was not enabled when
     *            wolfSSL was compiled.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws NullPointerException  Input URL is null
     * @see    #enableOCSP(long)
     * @see    #disableOCSP
     */
    public int setOCSPOverrideUrl(String url)
        throws IllegalStateException, NullPointerException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setOCSPOverrideUrl(getContextPtr(), url);
        }
    }

    /**
     * Allows caller to set the Atomic User Record Processing Mac/Encrypt
     * Callback.
     * The callback should return 0 for success, or less than 0 for an error.
     * The <b>ssl</b> and <b>ctx</b> pointers are available for the users
     * convenience. <b>macOut</b> is the output buffer where the result of the
     * mac should be stored. <b>macIn</b> is the mac input buffer and
     * <b>macinSz</b> notes the size of the buffer. <b>macContent</b> and
     * <b>macVerify</b> are needed for setTlsHmacInner() and can be passed
     * along as-is. <b>encOut</b> is the output buffer where the result on
     * encryption should be stored. <b>encIn</b> is the input buffer to encrypt
     * while <b>encSz</b> is the size of the input.<p>
     * An example Java callback can be found in
     * examples/MyMacEncryptCallback.java.
     *
     * @param callback  object to be registered as the MAC/encrypt
     *                  callback for the WolfSSL context. The signature of
     *                  this object and corresponding method must match that
     *                  as shown in
     *                  WolfSSLMacEncryptCallback.java, with
     *                  macEncryptCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setDecryptVerifyCb(WolfSSLDecryptVerifyCallback)
     */
    public synchronized void setMacEncryptCb(WolfSSLMacEncryptCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set MAC encrypt callback */
        internMacEncryptCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setMacEncryptCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Atomic Record Processing Decrypt/Verify
     * Callback.
     * The callback should return 0 for success, or a negative value for
     * an error. The <b>ssl</b> and <b>ctx</b> pointers are available
     * for the users convenience. <b>decOut</b> is the output buffer
     * where the result of the decryption should be stored. <b>decIn</b>
     * is the encrypted input buffer and <b>decInSz</b> notes the size of the
     * buffer. <b>context</b> and <b>verify</b> are needed for
     * setTlsHmacInner() and can be passed along as-is. <b>padSz</b> is
     * an output variable, where the first element in the array should be set
     * with the total value of the padding. That is, the mac size plus any
     * padding and pad bytes. An example callback can be found in
     * examples/MyDecryptVerifyCallback.java.
     *
     * @param callback  object to be registered as the decrypt/verify
     *                  callback for the WolfSSL context. The signature of
     *                  this object and corresponding method must match that
     *                  as shown in
     *                  WolfSSLDecryptVerifyCallback.java, inside
     *                  decryptVerifyCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    #setMacEncryptCb(WolfSSLMacEncryptCallback)
     */
    public synchronized void setDecryptVerifyCb(
        WolfSSLDecryptVerifyCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set decrypt/verify callback */
        internDecryptVerifyCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setDecryptVerifyCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for ECC Signing.
     * The callback should return 0 for success or a negative value for an
     * error. The <b>ssl</b> and <b>ctx</b> pointers are available for
     * the users convenience. <b>in</b> is the inptu buffer to sign while
     * <b>inSz</b> denotes the length of the input. <b>out</b> is the output
     * buffer where the result of the signature should be stored. <b>outSz</b>
     * is an input/output variable that specifies the size of the output buffer
     * upon invocation and the actual size of the signature should be stored
     * there before returning. <b>keyDer</b> is the ECC Private key in
     * ASN1 format and <b>keySz</b> is the length of the key in bytes. An
     * example callback can be found in examples/MyEccSignCallback.java.
     *
     * @param callback  object to be registered as the ECC signing callback
     *                  for the WolfSSL context. The signature of this
     *                  object and corresponding method must match that as
     *                  shown in WolfSSLEccSignCallback.java, inside
     *                  eccSignCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setEccSignCtx(Object)
     */
    public synchronized void setEccSignCb(WolfSSLEccSignCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set ecc sign callback */
        internEccSignCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setEccSignCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for ECC Verification.
     * The callback should return 0 for success or a negative value for an
     * error. The <b>ssl</b> and <b>ctx</b> pointers are available for the
     * users convenience. <b>sig</b> is the signature to verify and <b>sigSz</b>
     * denotes the length of the signature. <b>hash</b> is an input buffer
     * containing the digest of the message and <b>hashSz</b> denotes
     * the length in bytes of the hash. <b>result</b> is an output variable
     * where the result of the verification should be stored, <b>1</b> for
     * success and <b>0</b> for failure. <b>keyDer</b> is the ECC Private
     * key in ASN1 format and <b>keySz</b> is the length of the key in bytes.
     * An example callback can be found in examples/MyEccVerifyCallback.java.
     *
     * @param callback  object to be registered as the ECC verification
     *                  callback for the WolfSSL context. The signature of this
     *                  object and corresponding method must match that as
     *                  shown in WolfSSLEccVerifyCallback.java, inside
     *                  eccVerifyCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setEccVerifyCtx(Object)
     */
    public synchronized void setEccVerifyCb(WolfSSLEccVerifyCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set ecc verify callback */
        internEccVerifyCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setEccVerifyCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for ECC shared secret.
     * The callback should return 0 for success or a negative value for an
     * error.
     *
     * The <b>ssl</b> and <b>ctx</b> pointers are available for
     * the users convenience.
     *
     * <b>otherKey</b> is ByteBuffer with behavior that
     * depends on if the callback is called from the client or server side.
     * If <b>side</b> indicates client side, <b>otherKey</b> holds the server
     * public key for use with shared secret generation. If <b>side</b>
     * indicates server side, <b>otherKey</b> holds the server's private key.
     *
     * <b>pubKeyDer</b> behavior is also dependent on side. On the client side,
     * it is used as output for the client to write a DER-encoded public key.
     * On the server side, it is used as an input buffer containing a
     * DER-encoded public key of the peer (client).
     *
     * <b>out</b> is where the generated shared secret should be placed.
     *
     * <b>side</b> represents the side from which this callback was called.
     * Can be either WolfSSL.WOLFSSL_CLIENT_END or WolfSSL.WOLFSSL_SERVER_END.
     *
     * An example callback can be found in
     * examples/MyEccSharedSecretCallback.java
     *
     * @param callback  object to be registered as the ECC shared secret
     *                  callback for the WolfSSL context. The signature of this
     *                  object and corresponding method must match that as
     *                  shown in WolfSSLEccSharedSecretCallback.java, inside
     *                  eccSharedSecretCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setEccSignCtx(Object)
     * @see    WolfSSLSession#setEccVerifyCtx(Object)
     */
    public synchronized void setEccSharedSecretCb(
        WolfSSLEccSharedSecretCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set ecc shared secret callback */
        internEccSharedSecretCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setEccSharedSecretCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for RSA Signing.
     * The callback should return 0 for success or a negative value for an
     * error. The <b>ssl</b> and <b>ctx</b> pointers are available for the
     * users convenience. <b>in</b> is the input buffer to sign while
     * <b>inSz</b> denotes the length of the input. <b>out</b> is the output
     * buffer where the result of the signature should be stored. <b>outSz</b>
     * is an input/output variable that specifies the size of the output
     * buffer upon invocation. The actual size of the signature should
     * be stored there before returning. <b>keyDer</b> is the RSA Private key
     * in ASN1 format and <b>keySz</b> is the length of the key in bytes.
     * An example callback can be found in examples/MyRsaSignCallback.java.
     *
     * @param callback  object to be registered as the RSA signing callback
     *                  for the WolfSSL context. The signature of this object
     *                  and corresponding method must match that as shown
     *                  in WolfSSLRsaSignCallback.java, inside
     *                  rsaSignCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setRsaSignCtx(Object)
     */
    public synchronized void setRsaSignCb(WolfSSLRsaSignCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set rsa sign callback */
        internRsaSignCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setRsaSignCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for RSA Verification.
     * The callback should return the number of plaintext bytes for
     * success or a negative value for an error. The <b>ssl</b> and
     * <b>ctx</b> pointers are available for the users convenience. <b>sig</b>
     * is the signature to verify and <b>sigSz</b> denotes the length of the
     * signature. <b>out</b> should be set to the beginning of the verification
     * buffer after the decryption process and any padding. <b>outSz</b>
     * denotes the size size of the output buffer. <b>keyDer</b>
     * is the RSA Public key in ASN1 format and <b>keySz</b> is the length of
     * the key in bytes. An example can be found in
     * examples/MyRsaVerifyCallback.java.
     *
     * @param callback  object to be registered as the RSA verify callback
     *                  for the WolfSSL context. The signature of this
     *                  object and corresponding method must match that as
     *                  shown in WolfSSLRsaVerifyCallback.java, inside
     *                  rsaVerifyCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setRsaVerifyCtx(Object)
     */
    public synchronized void setRsaVerifyCb(WolfSSLRsaVerifyCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set rsa verify callback */
        internRsaVerifyCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setRsaVerifyCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key Callback for RSA Public Encrypt.
     * The callback should return 0 for success or negative value for an
     * error. The <b>ssl</b> and <b>ctx</b> objects are available for
     * the users convenience. <b>in</b> is the input buffer to encrypt while
     * <b>inSz</b> denotes the length of the input. <b>out</b> is the output
     * buffer where the result of the encryption should be stored. <b>outSz</b>
     * is an input/output variable that specifies the size of the output
     * buffer upon invocation and the actual size of the encryption should be
     * stored there before returning. <b>keyDer</b> is the RSA Public key in
     * ASN1 format and <b>keySz</b> is the length of the key in bytes. An
     * example callback can be found in examples/MyRsaEncCallback.java.
     *
     * @param callback  object to be registered as the RSA public encrypt
     *                  callback for the WolfSSL context. The signature of
     *                  this object and corresponding method must match that
     *                  as shown in WolfSSLRsaEncCallback.java, inside
     *                  rsaEncCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI exception
     * @see    WolfSSLSession#setRsaEncCtx(Object)
     */
    public synchronized void setRsaEncCb(WolfSSLRsaEncCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set rsa public encrypt callback */
        internRsaEncCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setRsaEncCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the Public Key for RSA Private Decrypt.
     * The callback should return the number of plaintext bytes for
     * success or a negative value for an error. The <b>ssl</b> and <b>ctx</b>
     * parameters are available for the users convenience. <b>in</b> is the
     * input buffer to decrypt and <b>inSz</b> denotes the length of the
     * input. <b>out</b> should be the decrypted buffer after the decryption
     * process and any padding, with <b>outSz</b> denoting the size of the
     * output buffer. <b>keyDer</b> is the RSA Private key in
     * ASN1 format and <b>keySz</b> is the length of the key in bytes. An
     * example callback can be found in examples/MyRsaDecCallback.java.
     *
     * @param callback  object to be registered as the RSA private decrypt
     *                  callback for the WolfSSL context. The signature of
     *                  this object and corresponding method must match that
     *                  as shown in WolfSSLRsaDecCallback.java, inside
     *                  rsaDecCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLSession#setRsaDecCtx(Object)
     */
    public synchronized void setRsaDecCb(WolfSSLRsaDecCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set rsa private decrypt callback */
        internRsaDecCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setRsaDecCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the PSK client identity, hint, and key.
     * The callback should return the length of the key in octets or
     * 0 for error. The <b>ssl</b> parameter is available for the user's
     * convenience. <b>hint</b> is the client PSK hint. <b>identity</b>
     * is the client identity, with a maximum size in characters of
     * <b>idMaxLen</b>. <b>key</b> is the client key, with a maximum size
     * in bytes of <b>keyMaxLen</b>. An example callback can be found
     * in examples/MyPskClientCallback.java.
     *
     * @param callback object to be registered as the PSK client callback
     *                 for the WolfSSLContext. The signature of this object
     *                 and corresponding method must match that as shown in
     *                 WolfSSLPskClientCallback.java, inside
     *                 pskClientCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#getPskIdentityHint()
     * @see    WolfSSLSession#usePskIdentityHint(String)
     */
    public synchronized void setPskClientCb(WolfSSLPskClientCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set PSK client callback */
        internPskClientCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setPskClientCb(getContextPtr());
        }
    }

    /**
     * Allows caller to set the PSK server identity and key.
     * The callback should return the length of the key in octets or
     * 0 for error. The <b>ssl</b> parameter is available for the user's
     * convenience. <b>identity</b> is the client identity,
     * <b>key</b> is the server key, with a maximum size
     * in bytes of <b>keyMaxLen</b>. An example callback can be found
     * in examples/MyPskServerCallback.java.
     *
     * @param callback object to be registered as the PSK server callback
     *                 for the WolfSSLContext. The signature of this object
     *                 and corresponding method must match that as shown in
     *                 WolfSSLPskServerCallback.java, inside
     *                 pskServerCallback().
     * @throws IllegalStateException WolfSSLContext has been freed
     * @throws WolfSSLJNIException Internal JNI error
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#getPskIdentityHint()
     * @see    WolfSSLSession#usePskIdentityHint(String)
     */
    public synchronized void setPskServerCb(WolfSSLPskServerCallback callback)
        throws IllegalStateException, WolfSSLJNIException {

        confirmObjectIsActive();

        /* set PSK server callback */
        internPskServerCb = callback;

        /* register internal callback with native library */
        synchronized (ctxLock) {
            setPskServerCb(getContextPtr());
        }
    }

    /**
     * Sets the identity hint for this context.
     *
     * @param  hint  identity hint to be used for session.
     * @return <code>SSL_SUCCESS</code> upon success,
     *         <code>SSL_FAILURE</code> upon error.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLContext#usePskIdentityHint(String)
     * @see    WolfSSLSession#setPskClientCb(WolfSSLPskClientCallback)
     * @see    WolfSSLSession#setPskServerCb(WolfSSLPskServerCallback)
     * @see    WolfSSLSession#getPskIdentity()
     * @see    WolfSSLSession#getPskIdentityHint()
     * @see    WolfSSLSession#usePskIdentityHint(String)
     */
    public int usePskIdentityHint(String hint) {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return usePskIdentityHint(getContextPtr(), hint);
        }
    }

    /**
     * Sets the TLS Supported Curves to be used in the ClientHello
     * extension if enabled in native wolfSSL.
     *
     * @param curveNames String array of ECC curve names to set into the
     *        Supported Curve extension. String values should match names from
     *        the following list:
     *            "sect163k1", "sect163r1", "sect163r2", "sect193r1",
     *            "sect193r2", "sect233k1", "sect233r1", "sect239k1",
     *            "sect283k1", "sect283r1", "sect409k1", "sect409r1",
     *            "sect571k1", "sect571r1", "secp160k1", "secp160r1",
     *            "secp160r2", "secp192k1", "secp192r1", "secp224k1",
     *            "secp224r1", "secp256k1", "secp256r1", "secp384r1",
     *            "secp521r1", "brainpoolP256r1", "brainpoolP384r1",
     *            "brainpoolP512r1", "x25519", "x448", "sm2P256v1",
     *            "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144",
     *            "ffdhe8192"
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise
     *         negative on error.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int useSupportedCurves(String[] curveNames)
        throws IllegalStateException {

        int ret = 0;
        int curveEnum = 0;

        for (String curve : curveNames) {
            curveEnum = WolfSSL.getNamedGroupFromString(curve);
            synchronized (ctxLock) {
                ret = useSupportedCurve(getContextPtr(), curveEnum);
            }
        }

        return ret;
    }

    /**
     * Sets the key exchange groups in rank order on this WolfSSLContext.
     *
     * @param groups Array of key exchange groups to be set. Values should
     *        come from com.wolfssl.WolfSSL section for Named Groups, for
     *        example:
     *                WOLFSSL_ECC_SECT163R1
     *                WOLFSSL_ECC_SECT163R2
     *                WOLFSSL_ECC_SECT193R1
     *                WOLFSSL_ECC_SECT193R2
     *                WOLFSSL_ECC_SECT233K1
     *                WOLFSSL_ECC_SECT233R1
     *                WOLFSSL_ECC_SECT239K1
     *                WOLFSSL_ECC_SECT283K1
     *                WOLFSSL_ECC_SECT283R1
     *                WOLFSSL_ECC_SECT409K1
     *                WOLFSSL_ECC_SECT409R1
     *                WOLFSSL_ECC_SECT571K1
     *                WOLFSSL_ECC_SECT571R1
     *                WOLFSSL_ECC_SECP160K1
     *                WOLFSSL_ECC_SECP160R1
     *                WOLFSSL_ECC_SECP160R2
     *                WOLFSSL_ECC_SECP192K1
     *                WOLFSSL_ECC_SECP192R1
     *                WOLFSSL_ECC_SECP224K1
     *                WOLFSSL_ECC_SECP224R1
     *                WOLFSSL_ECC_SECP256K1
     *                WOLFSSL_ECC_SECP256R1
     *                WOLFSSL_ECC_SECP384R1
     *                WOLFSSL_ECC_SECP521R1
     *                WOLFSSL_ECC_BRAINPOOLP256R1
     *                WOLFSSL_ECC_BRAINPOOLP384R1
     *                WOLFSSL_ECC_BRAINPOOLP512R1
     *                WOLFSSL_ECC_X25519
     *                WOLFSSL_ECC_X448
     *                WOLFSSL_ECC_SM2P256V1
     *                WOLFSSL_FFDHE_2048
     *                WOLFSSL_FFDHE_3072
     *                WOLFSSL_FFDHE_4096
     *                WOLFSSL_FFDHE_6144
     *                WOLFSSL_FFDHE_8192
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise negative
     *         value on error. BAD_FUNC_ARG when groups is null, not using
     *         TLS 1.3 or size is greater than WOLFSSL_MAX_GROUP_COUNT (which
     *         defaults to 10, unless HAVE_PQC is defined then is 36.
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int setGroups(int[] groups)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setGroups(getContextPtr(), groups);
        }
    }

    /**
     * Set the supported signature algorithms for this WolfSSLContext. This
     * replaces the existing or default list in the context.
     *
     * @param list Colon-separated list of [public key]+[digest] algorithms,
     *             for example: "RSA+SHA256", or "RSA+SHA256:ECDSA:SHA256"
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise
     *         <code>WolfSSL.SSL_FAILURE</code> on failure
     * @throws IllegalStateException WolfSSLContext has been freed
     */
    public int set1SigAlgsList(String list)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return set1SigAlgsList(getContextPtr(), list);
        }
    }

    /**
     * Enable use of secure renegotiation on this session. Calling this
     * API does not initiate secure renegotiation, but enables it. If enabled,
     * and peer requests secure renegotiation, this session will renegotiate.
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> on success, otherwise negative.
     *         Will return <code>WolfSSL.NOT_COMPILED_IN</code> if native
     *         wolfSSL has not been compiled with
     *         <code>HAVE_SECURE_RENEGOTIATION</code>.
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int useSecureRenegotiation() throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return useSecureRenegotiation(getContextPtr());
        }
    }

    /**
     * Set minimum supported DH key size for this WOLFSSL_CTX.
     *
     * @param minKeySizeBits Minimum DH key size in bits (ex: 1024)
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> upon success,
     *         <code>WolfSSL.SSL_FAILURE</code> or negative upon error.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#setMinRSAKeySize(int)
     * @see    WolfSSLContext#setMinECCKeySize(int)
     */
    public int setMinDHKeySize(int minKeySizeBits)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setMinDhKeySz(getContextPtr(), minKeySizeBits);
        }
    }

    /**
     * Set minimum supported RSA key size for this WOLFSSL_CTX.
     *
     * @param minKeySizeBits Minimum RSA key size in bits (ex: 2048)
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> upon success,
     *         <code>WolfSSL.SSL_FAILURE</code> or negative upon error.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#setMinDHKeySize(int)
     * @see    WolfSSLContext#setMinECCKeySize(int)
     */
    public int setMinRSAKeySize(int minKeySizeBits)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setMinRsaKeySz(getContextPtr(), minKeySizeBits);
        }
    }

    /**
     * Set minimum supported ECC key size for this WOLFSSL_CTX.
     *
     * @param minKeySizeBits Minimum ECC key size in bits (ex: 224)
     *
     * @return <code>WolfSSL.SSL_SUCCESS</code> upon success,
     *         <code>WolfSSL.SSL_FAILURE</code> or negative upon error.
     * @throws IllegalStateException WolfSSLContext has been freed
     * @see    WolfSSLContext#setMinDHKeySize(int)
     * @see    WolfSSLContext#setMinRSAKeySize(int)
     */
    public int setMinECCKeySize(int minKeySizeBits)
        throws IllegalStateException {

        confirmObjectIsActive();

        synchronized (ctxLock) {
            return setMinEccKeySz(getContextPtr(), minKeySizeBits);
        }
    }

    /**
     * Set crypto callback devId to be used with this WOLFSSL_CTX.
     *
     * Called by com.wolfssl.provider.jsse.WolfSSLContext.
     *
     * @param devId devId to use with crypto callback implementation.
     * @return WolfSSL.SSL_SUCCESS on success, negative on error
     *
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public int setDevId(int devId) throws IllegalStateException {

        confirmObjectIsActive();

        return setDevId(getContextPtr(), devId);
    }

    /**
     * Remove / flush expired sessions from the native wolfSSL session cache.
     *
     * @param tm the time used to determine the expiration date for sessions,
     *           should be result of equivalent of native time(0), or
     *           desired expiration time in seconds from the unix epoch
     *           (Jan 1, 1970).
     * @throws IllegalStateException WolfSSLSession has been freed
     */
    public void flushSessions(int tm) throws IllegalStateException {

        confirmObjectIsActive();

        flushSessions(getContextPtr(), tm);
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        try {
            /* free() checks and resets this.active */
            this.free();
        } catch (IllegalStateException e) {
            /* already freed */
        }
        super.finalize();
    }

} /* end WolfSSLContext */
