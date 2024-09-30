/* WolfSSL.java
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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.FileNotFoundException;

/**
 * Base class which wraps the native WolfSSL embedded SSL library.
 * This class contains library init and cleanup methods, general callback
 * methods, as well as error codes and general wolfSSL codes.
 *
 * @author  wolfSSL
 */
public class WolfSSL {

    /* If this enum is changed, also change switch statement cases in
     * ./native/com_wolfssl_WolfSSL.c,
     * Java_com_wolfssl_WolfSSL_getAvailableCipherSuitesIana() */
    /** TLS protocol versions */
    public enum TLS_VERSION {
        /** invalid TLS version */
        INVALID,
        /** TLS 1.0 */
        TLSv1,
        /** TLS 1.1 */
        TLSv1_1,
        /** TLS 1.2 */
        TLSv1_2,
        /** TLS 1.3 */
        TLSv1_3,
        /** Downgrade starting from highest supported SSL/TLS version */
        SSLv23
    }

    /* ------------------ wolfSSL JNI error codes ----------------------- */
    /** Session unavailable */
    public static final int JNI_SESSION_UNAVAILABLE = -10001;

    /**
     * Socket select/poll() failed, matches com_wolfssl_WolfSSLSession.c
     * socketSelect() and socketPoll() return value.
     */
    public static final int WOLFJNI_IO_EVENT_FAIL = -10;

    /**
     * Socket timed out, matches com_wolfssl_WolfSSLSession.c
     * socketSelect() and socketPoll() return value.
     */
    public static final int WOLFJNI_IO_EVENT_TIMEOUT = -11;

    /**
     * Socket poll() exceptional error, matches com_wolfssl_WolfSSLSession.c
     * socketPoll() return value */
    public static final int WOLFJNI_IO_EVENT_ERROR = -14;

    /**
     * Socket file descriptor closed, matches com_wolfssl_WolfSSLSession.c
     * socketPoll() return value */
    public static final int WOLFJNI_IO_EVENT_FD_CLOSED = -15;

    /**
     * Socket disconnected during poll(), matches
     * com_wolfssl_WolfSSLSession.c socketPoll() return value */
    public static final int WOLFJNI_IO_EVENT_POLLHUP = -16;

    /**
     * Socket invalid timeout during poll/select(), matches
     * com_wolfssl_WolfSSLSession.c socketPoll/socketSelect() return value */
    public static final int WOLFJNI_IO_EVENT_INVALID_TIMEOUT = -17;

    /* ----------------------- wolfSSL codes ---------------------------- */

    /** Error code: no error */
    public static final int SSL_ERROR_NONE      =  0;
    /** Error code: failure */
    public static final int SSL_FAILURE         =  0;
    /** Error code: success */
    public static final int SSL_SUCCESS         =  1;
    /** Error code: TLS shutdown not done */
    public static final int SSL_SHUTDOWN_NOT_DONE = 2;

    /** Error code: bad certificate */
    public static final int SSL_BAD_CERTTYPE    = -8;
    /** Error code: bad file stat */
    public static final int SSL_BAD_STAT        = -7;
    /** Error code: bad path */
    public static final int SSL_BAD_PATH        = -6;
    /** Error code: bad file type */
    public static final int SSL_BAD_FILETYPE    = -5;
    /** Error code: bad file */
    public static final int SSL_BAD_FILE        = -4;
    /** Error code: not implemented */
    public static final int SSL_NOT_IMPLEMENTED = -3;
    /** Error code: unknown */
    public static final int SSL_UNKNOWN         = -2;
    /** Error code: fatal error */
    public static final int SSL_FATAL_ERROR     = -1;

    /** wolfSSL file type: ASN.1/DER */
    public static final int SSL_FILETYPE_ASN1    = 2;
    /** wolfSSL file type: PEM */
    public static final int SSL_FILETYPE_PEM     = 1;
    /** ASN1 */
    public static final int SSL_FILETYPE_DEFAULT = 2;
    /** NTRU raw key blog */
    public static final int SSL_FILETYPE_RAW     = 3;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will not verify the certificate
     * received from the server and the handshake will continue as normal.
     * <br>
     * <b>Server mode:</b> the server will not send a certificate request
     * to the client. As such, client verification will not be enabled.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_NONE = 0;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> the client will verify the certificate received
     * from the server during the handshake. This is turned on by default
     * in wolfSSL, therefore, using this option has no effect.
     * <br>
     * <b>Server mode:</b> the server will send a certificate request to the
     * client and verify the client certificate which is received.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_PEER = 1;

    /**
     * Verification mode for peer certificates.
     * <p>
     * <b>Client mode:</b> no effect when used on the client side.
     * <br>
     * <b>Server mode:</b> the verification will fail on the server side
     * if the client fails to send a certificate when requested to do so
     * (when using SSL_VERIFY_PEER on the SSL server).
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_FAIL_IF_NO_PEER_CERT = 2;

    /**
     * Verification mode for peer certificates.
     * Currently not supported by native wolfSSL.
     *
     * @see WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
     */
    public static final int SSL_VERIFY_CLIENT_ONCE          = 4;

    /** Disable session cache */
    public static final int SSL_SESS_CACHE_OFF                = 30;
    /** currently unused */
    public static final int SSL_SESS_CACHE_CLIENT             = 31;
    /** Native session cache mode: server */
    public static final int SSL_SESS_CACHE_SERVER             = 32;
    /** currently unused */
    public static final int SSL_SESS_CACHE_BOTH               = 33;
    /** Native session cache mode: auto flush */
    public static final int SSL_SESS_CACHE_NO_AUTO_CLEAR      = 34;
    /** currently unused */
    public static final int SSL_SESS_CACHE_NO_INTERNAL_LOOKUP = 35;

    /** I/O read would block, wolfSSL needs more data */
    public static final int SSL_ERROR_WANT_READ        =  2;
    /** I/O send would block, wolfSSL needs to write data */
    public static final int SSL_ERROR_WANT_WRITE       =  3;
    /** currently unused */
    public static final int SSL_ERROR_WANT_CONNECT     =  7;
    /** currently unused */
    public static final int SSL_ERROR_WANT_ACCEPT      =  8;
    /** Error with underlying I/O */
    public static final int SSL_ERROR_SYSCALL          =  5;
    /** I/O operation should be called again when client cert is available */
    public static final int SSL_ERROR_WANT_X509_LOOKUP = 83;
    /** I/O error, zero return, no more data */
    public static final int SSL_ERROR_ZERO_RETURN      =  6;
    /** Generatl SSL error */
    public static final int SSL_ERROR_SSL              = 85;
    /** Received fatal alert error */
    public static final int FATAL_ERROR                = -313;
    /** Peer closed socket */
    public static final int SSL_ERROR_SOCKET_PEER_CLOSED = -397;
    /** Unrecognized ALPN protocol name */
    public static final int UNKNOWN_ALPN_PROTOCOL_NAME_E = -405;

    /* extra definitions from ssl.h */
    /** CertManager: check all cert CRLs */
    public static final int WOLFSSL_CRL_CHECKALL      = 1;
    /** CertManager: use override URL instead of URL in certificates */
    public static final int WOLFSSL_OCSP_URL_OVERRIDE = 1;
    /** CertManager: disable sending OCSP nonce */
    public static final int WOLFSSL_OCSP_NO_NONCE     = 2;

    /* ALPN definitions from ssl.h */
    /** ALPN: no match found */
    public static final int WOLFSSL_ALPN_NO_MATCH = 0;
    /** ALPN: found match */
    public static final int WOLFSSL_ALPN_MATCH    = 1;
    /** ALPN: continue on protocol mismatch */
    public static final int WOLFSSL_ALPN_CONTINUE_ON_MISMATCH = 2;
    /** ALPN: failed on protocol mismatch */
    public static final int WOLFSSL_ALPN_FAILED_ON_MISMATCH   = 4;

    /* I/O callback default errors, pulled from wolfssl/ssl.h IOerrors */
    /** I/O callback error: general error */
    public static final int WOLFSSL_CBIO_ERR_GENERAL    = -1;
    /** I/O callback error: want read */
    public static final int WOLFSSL_CBIO_ERR_WANT_READ  = -2;
    /** I/O callback error: want write */
    public static final int WOLFSSL_CBIO_ERR_WANT_WRITE = -2;
    /** I/O callback error: connection reset */
    public static final int WOLFSSL_CBIO_ERR_CONN_RST   = -3;
    /** I/O callback error: socket interrupted */
    public static final int WOLFSSL_CBIO_ERR_ISR        = -4;
    /** I/O callback error: connection closed */
    public static final int WOLFSSL_CBIO_ERR_CONN_CLOSE = -5;
    /** I/O callback error: timeout */
    public static final int WOLFSSL_CBIO_ERR_TIMEOUT    = -6;

    /* Atomic User Needs, from ssl.h */
    /** Represents server side */
    public static final int WOLFSSL_SERVER_END  = 0;
    /** Represents Client side */
    public static final int WOLFSSL_CLIENT_END  = 1;
    /** wolfSSL block algorithm type */
    public static final int WOLFSSL_BLOCK_TYPE  = 2;
    /** wolfSSL stream algorithm type */
    public static final int WOLFSSL_STREAM_TYPE = 3;
    /** wolfSSL AEAD algorithm type */
    public static final int WOLFSSL_AEAD_TYPE   = 4;
    /** wolfSSL TLS HMAC inner size */
    public static final int WOLFSSL_TLS_HMAC_INNER_SZ = 13;

    /* GetBulkCipher enum, pulled in from ssl.h for Atomic Record layer */
    /** Bulk cipher algorithm enum: NULL */
    public static int wolfssl_cipher_null;
    /** Bulk cipher algorithm enum: RC4 */
    public static int wolfssl_rc4;
    /** Bulk cipher algorithm enum: RC2 */
    public static int wolfssl_rc2;
    /** Bulk cipher algorithm enum: DES */
    public static int wolfssl_des;
    /** Bulk cipher algorithm enum: 3DES */
    public static int wolfssl_triple_des;
    /** Bulk cipher algorithm enum: DES40 */
    public static int wolfssl_des40;
    /** Bulk cipher algorithm enum: AES */
    public static int wolfssl_aes;
    /** Bulk cipher algorithm enum: AES-GCM */
    public static int wolfssl_aes_gcm;
    /** Bulk cipher algorithm enum: AES-CCM */
    public static int wolfssl_aes_ccm;

    /* wolfSSL error codes, pulled in from wolfssl/error.h wolfSSL_ErrorCodes */
    /** Generate Cookie Error */
    public static final int GEN_COOKIE_E    =   -277;

    /** Close notify alert sent */
    public static final int SSL_SENT_SHUTDOWN                   = 1;
    /** Close notify alert received */
    public static final int SSL_RECEIVED_SHUTDOWN               = 2;
    /** Make it possible to return SSL write with changed buffer location */
    public static final int SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 4;
    /** Disable SSL 2.0. wolfSSL does not support SSL 2.0. */
    public static final int SSL_OP_NO_SSLv2                     = 8;
    /** Disable SSL 3.0 */
    public static final int SSL_OP_NO_SSLv3                     = 0x00001000;
    /** Disable TLS 1.0 */
    public static final int SSL_OP_NO_TLSv1                     = 0x00002000;
    /** Disable TLS 1.1 */
    public static final int SSL_OP_NO_TLSv1_1                   = 0x04000000;
    /** Disable TLS 1.2 */
    public static final int SSL_OP_NO_TLSv1_2                   = 0x08000000;
    /** Disable TLS compression. Off by default */
    public static final int SSL_OP_NO_COMPRESSION               = 0x10000000;
    /** Disable TLS 1.3 */
    public static final int SSL_OP_NO_TLSv1_3                   = 0x20000000;

    /** SSL/TLS handshake failure */
    public static final int SSL_HANDSHAKE_FAILURE                 = 101;
    /** Alert: Unknown CA */
    public static final int SSL_R_TLSV1_ALERT_UNKNOWN_CA          = 102;
    /** Alert: Certificate Unknown */
    public static final int SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN = 103;
    /** Alert: Bad certificate */
    public static final int SSL_R_SSLV3_ALERT_BAD_CERTIFICATE     = 104;

    /** Monitor this CRL directory flag */
    public static final int WOLFSSL_CRL_MONITOR   = 0x01;

    /** Start CRL monitoring flag */
    public static final int WOLFSSL_CRL_START_MON = 0x02;

    /** Bad mutex */
    public static final int BAD_MUTEX_ERROR      = -256;

    /** Bad path for opendir */
    public static final int BAD_PATH_ERROR       = -258;

    /** CRL Monitor already running */
    public static final int MONITOR_RUNNING_E    = -263;

    /** Thread create error */
    public static final int THREAD_CREATE_E      = -264;

    /** Cache header match error */
    public static final int CACHE_MATCH_ERROR    = -280;

    /* ------------------ TLS extension specific  ------------------------ */
    /** SNI Host name type, for UseSNI() */
    public static final int WOLFSSL_SNI_HOST_NAME = 0;

    /** ALPN ERR OK, ALPN protocol match */
    public static final int SSL_TLSEXT_ERR_OK = 0;

    /** ALPN ERR NOACK, ALPN callback no match but not fatal */
    public static final int SSL_TLSEXT_ERR_NOACK = 3;

    /** ALPN ERR FATAL, ALPN callback no match and fatal */
    public static final int SSL_TLSEXT_ERR_ALERT_FATAL = 2;

    /* ----------------- TLS 1.3 secret callback IDs  -------------------- */
    /** TLS 1.3 secret ID: client early traffic secret */
    public static int CLIENT_EARLY_TRAFFIC_SECRET;

    /** TLS 1.3 secret ID: client handshake traffic secret */
    public static int CLIENT_HANDSHAKE_TRAFFIC_SECRET;

    /** TLS 1.3 secret ID: server handshake traffic secret */
    public static int SERVER_HANDSHAKE_TRAFFIC_SECRET;

    /** TLS 1.3 secret ID: client traffic secret */
    public static int CLIENT_TRAFFIC_SECRET;

    /** TLS 1.3 secret ID: server traffic secret */
    public static int SERVER_TRAFFIC_SECRET;

    /** TLS 1.3 secret ID: early exporter secret */
    public static int EARLY_EXPORTER_SECRET;

    /** TLS 1.3 secret ID: exporter secret */
    public static int EXPORTER_SECRET;

    /* ---------------------- wolfCrypt codes ---------------------------- */

    /** Out of memory error */
    public static final int MEMORY_E        = -125;

    /** Output buffer too small or input too large */
    public static final int BUFFER_E        = -132;

    /** ASN input error, not enough data */
    public static final int ASN_INPUT_E     = -154;

    /** Bad function argument provided */
    public static final int BAD_FUNC_ARG    = -173;

    /** Feature not compiled in */
    public static final int NOT_COMPILED_IN = -174;

    /** No password provided by user */
    public static final int NO_PASSWORD     = -176;

    /** TLS 1.3 secret callback function failure */
    public static final int TLS13_SECRET_CB_E = -438;

    /* hmac codes, from wolfssl/wolfcrypt/hmac.h */
    /** Md5 HMAC type */
    public static final int MD5   = 0;
    /** SHA-1 HMAC type */
    public static final int SHA   = 1;
    /** SHA2-256 HMAC type */
    public static final int SHA256 = 2;
    /** SHA2-512 HMAC type */
    public static final int SHA512 = 4;
    /** SHA2-384 HMAC type */
    public static final int SHA384 = 5;

    /* key types */
    /** DSA key type */
    public static final int DSAk     = 515;
    /** RSA key type */
    public static final int RSAk     = 645;
    /** NTRU key type */
    public static final int NTRUk    = 274;
    /** ECDSA key type */
    public static final int ECDSAk   = 518;
    /** Ed25519 key type */
    public static final int ED25519k = 256;

    /* GeneralName types. Match native values in asn.h */
    /** ASN other type */
    public static final int ASN_OTHER_TYPE  = 0x00;
    /** ASN RFC822 type */
    public static final int ASN_RFC822_TYPE = 0x01;
    /** ASN DNS type */
    public static final int ASN_DNS_TYPE    = 0x02;
    /** ASN DIR/directory type */
    public static final int ASN_DIR_TYPE    = 0x04;
    /** ASN URI type */
    public static final int ASN_URI_TYPE    = 0x06;
    /** ASN IP type */
    public static final int ASN_IP_TYPE     = 0x07;

    /* NIDs, from native asn.h */
    /** Surname NID */
    public static final int NID_surname                 = 4;
    /** Serial number NID */
    public static final int NID_serialNumber            = 5;
    /** PKCS9 Unstructured name NID */
    public static final int NID_pkcs9_unstructuredName  = 49;
    /** PKCS9 contentType NID */
    public static final int NID_pkcs9_contentType       = 50;
    /** PKCS9 challenge password NID */
    public static final int NID_pkcs9_challengePassword = 54;
    /** Given name NID */
    public static final int NID_givenName               = 100;
    /** Initials NID */
    public static final int NID_initials                = 101;
    /** Key Usage NID */
    public static final int NID_key_usage               = 129;
    /** Subject Alternative Name NID */
    public static final int NID_subject_alt_name        = 131;
    /** Basic Constraints NID */
    public static final int NID_basic_constraints       = 133;
    /** Extended Key Usage NID */
    public static final int NID_ext_key_usage           = 151;
    /** Domain name qualifier NID */
    public static final int NID_dnQualifier             = 174;

    /* is this object active, or has it been cleaned up? */
    private boolean active = false;

    /* -------------- Named Groups (from enum in ssl.h) ----------------- */
    /** Invalid named group */
    public static final int WOLFSSL_NAMED_GROUP_INVALID = 0;
    /** ECC SECT163K1 */
    public static final int WOLFSSL_ECC_SECT163K1 = 1;
    /** ECC SECT163R1 */
    public static final int WOLFSSL_ECC_SECT163R1 = 2;
    /** ECC SECT163R2 */
    public static final int WOLFSSL_ECC_SECT163R2 = 3;
    /** ECC SECT193R1 */
    public static final int WOLFSSL_ECC_SECT193R1 = 4;
    /** ECC SECT193R2 */
    public static final int WOLFSSL_ECC_SECT193R2 = 5;
    /** ECC SECT233K1 */
    public static final int WOLFSSL_ECC_SECT233K1 = 6;
    /** ECC SECT233R1 */
    public static final int WOLFSSL_ECC_SECT233R1 = 7;
    /** ECC SECT239K1 */
    public static final int WOLFSSL_ECC_SECT239K1 = 8;
    /** ECC SECT283K1 */
    public static final int WOLFSSL_ECC_SECT283K1 = 9;
    /** ECC SECT283R1 */
    public static final int WOLFSSL_ECC_SECT283R1 = 10;
    /** ECC SECT409K1 */
    public static final int WOLFSSL_ECC_SECT409K1 = 11;
    /** ECC SECT409R1 */
    public static final int WOLFSSL_ECC_SECT409R1 = 12;
    /** ECC SECT571K1 */
    public static final int WOLFSSL_ECC_SECT571K1 = 13;
    /** ECC SECT571R1 */
    public static final int WOLFSSL_ECC_SECT571R1 = 14;
    /** ECC SECP160K1 */
    public static final int WOLFSSL_ECC_SECP160K1 = 15;
    /** ECC SECP160R1 */
    public static final int WOLFSSL_ECC_SECP160R1 = 16;
    /** ECC SECP160R2 */
    public static final int WOLFSSL_ECC_SECP160R2 = 17;
    /** ECC SECP192K1 */
    public static final int WOLFSSL_ECC_SECP192K1 = 18;
    /** ECC SECP192R1 */
    public static final int WOLFSSL_ECC_SECP192R1 = 19;
    /** ECC SECP224K1 */
    public static final int WOLFSSL_ECC_SECP224K1 = 20;
    /** ECC SECP224R1 */
    public static final int WOLFSSL_ECC_SECP224R1 = 21;
    /** ECC SECP256K1 */
    public static final int WOLFSSL_ECC_SECP256K1 = 22;
    /** ECC SECP256R1 */
    public static final int WOLFSSL_ECC_SECP256R1 = 23;
    /** ECC SECP384R1 */
    public static final int WOLFSSL_ECC_SECP384R1 = 24;
    /** ECC SECP521R1 */
    public static final int WOLFSSL_ECC_SECP521R1 = 25;
    /** ECC BRAINPOOLP256R1 */
    public static final int WOLFSSL_ECC_BRAINPOOLP256R1 = 26;
    /** ECC BRAINPOOLP384R1 */
    public static final int WOLFSSL_ECC_BRAINPOOLP384R1 = 27;
    /** ECC BRAINPOOLP512R1 */
    public static final int WOLFSSL_ECC_BRAINPOOLP512R1 = 28;
    /** ECC X25519 */
    public static final int WOLFSSL_ECC_X25519    = 29;
    /** ECC X448 */
    public static final int WOLFSSL_ECC_X448      = 30;
    /** ECC SM2P256V1 */
    public static final int WOLFSSL_ECC_SM2P256V1 = 41;
    /** FFDHE 2048 */
    public static final int WOLFSSL_FFDHE_2048    = 256;
    /** FFDHE 3072 */
    public static final int WOLFSSL_FFDHE_3072    = 257;
    /** FFDHE 4096 */
    public static final int WOLFSSL_FFDHE_4096    = 258;
    /** FFDHE 6144 */
    public static final int WOLFSSL_FFDHE_6144    = 259;
    /** FFDHE 8192 */
    public static final int WOLFSSL_FFDHE_8192    = 260;

    /* -------------------- Crypto Callback DevID ----------------------- */
    /** Invalid DevID value, when used as devId software crypto is used */
    public static final int INVALID_DEVID = -2;

    /** Crypto callback devId to be used by wolfSSL for WOLFSSL and
     * WOLFSSL_CTX. This static devId will be used by wolfJSSE and set for all
     * WolfSSLContext objects, if set to something besides
     * WolfSSL.INVALID_DEVID. Applications can set this in wolfJSSE via
     * WolfSSLProvider.setDevId(), or on a per SSLContext and SSLSession
     * level with WolfSSLContext.setDevId() and WolfSSLSession.setDevId() */
    public static int devId = WolfSSL.INVALID_DEVID;

    /* ---------------------------- locks ------------------------------- */

    /* lock for cleanup */
    private final Object cleanupLock = new Object();

    /* ------------------------ constructors ---------------------------- */

    /**
     * Initializes the wolfSSL library for use.
     *
     * @throws com.wolfssl.WolfSSLException if wolfSSL library fails to
     *                                      initialize correctly
     */
    public WolfSSL() throws WolfSSLException {
        int ret = init();
        if (ret != SSL_SUCCESS) {
            throw new WolfSSLException("Failed to initialize wolfSSL library: "
                    + ret);
        }

        /* initialize enum values */
        wolfssl_aes         = getBulkCipherAlgorithmEnumAES();
        wolfssl_cipher_null = getBulkCipherAlgorithmEnumNULL();
        wolfssl_rc4         = getBulkCipherAlgorithmEnumRC4();
        wolfssl_rc2         = getBulkCipherAlgorithmEnumRC2();
        wolfssl_des         = getBulkCipherAlgorithmEnumDES();
        wolfssl_triple_des  = getBulkCipherAlgorithmEnumDES();
        wolfssl_des40       = getBulkCipherAlgorithmEnumDES40();
        wolfssl_aes_gcm     = getBulkCipherAlgorithmEnumAESGCM();
        wolfssl_aes_ccm     = getBulkCipherAlgorithmEnumAESCCM();

        /* initialize TLS 1.3 secret callback ID enums */
        CLIENT_EARLY_TRAFFIC_SECRET =
            getTls13SecretEnum_CLIENT_EARLY_TRAFFIC_SECRET();
        CLIENT_HANDSHAKE_TRAFFIC_SECRET =
            getTls13SecretEnum_CLIENT_HANDSHAKE_TRAFFIC_SECRET();
        SERVER_HANDSHAKE_TRAFFIC_SECRET =
            getTls13SecretEnum_SERVER_HANDSHAKE_TRAFFIC_SECRET();
        CLIENT_TRAFFIC_SECRET =
            getTls13SecretEnum_CLIENT_TRAFFIC_SECRET();
        SERVER_TRAFFIC_SECRET =
            getTls13SecretEnum_SERVER_TRAFFIC_SECRET();
        EARLY_EXPORTER_SECRET =
            getTls13SecretEnum_EARLY_EXPORTER_SECRET();
        EXPORTER_SECRET =
            getTls13SecretEnum_EXPORTER_SECRET();

        this.active = true;
    }

    /* ------------------- private/protected methods -------------------- */

    private native int init();

    /**
     * Free native memory allocated at pointer provided.
     * @param ptr native pointer
     */
    public static native void nativeFree(long ptr);

    static native int getBulkCipherAlgorithmEnumNULL();
    static native int getBulkCipherAlgorithmEnumRC4();
    static native int getBulkCipherAlgorithmEnumRC2();
    static native int getBulkCipherAlgorithmEnumDES();
    static native int getBulkCipherAlgorithmEnum3DES();
    static native int getBulkCipherAlgorithmEnumDES40();
    static native int getBulkCipherAlgorithmEnumAES();
    static native int getBulkCipherAlgorithmEnumAESGCM();
    static native int getBulkCipherAlgorithmEnumAESCCM();
    static native int getBulkCipherAlgorithmEnumCHACHA();
    static native int getBulkCipherAlgorithmEnumCAMELLIA();

    static native int getTls13SecretEnum_CLIENT_EARLY_TRAFFIC_SECRET();
    static native int getTls13SecretEnum_CLIENT_HANDSHAKE_TRAFFIC_SECRET();
    static native int getTls13SecretEnum_SERVER_HANDSHAKE_TRAFFIC_SECRET();
    static native int getTls13SecretEnum_CLIENT_TRAFFIC_SECRET();
    static native int getTls13SecretEnum_SERVER_TRAFFIC_SECRET();
    static native int getTls13SecretEnum_EARLY_EXPORTER_SECRET();
    static native int getTls13SecretEnum_EXPORTER_SECRET();

    static native String getEnabledCipherSuites();
    static native String getEnabledCipherSuitesIana();
    static native String getAvailableCipherSuitesIana(int version);

    /** Native wrapper to set wolfSSL crypto callback, only passing in devId
     * and allowing native code to set up and manage callback and context */
    private static native int wc_CryptoCb_RegisterDevice(int devId);

    /** Native wrapper to unregister wolfSSL crypto callback */
    private static native void wc_CryptoCb_UnRegisterDevice(int devId);

    /* ------------------------- Java methods --------------------------- */

    /**
     * Loads JNI library; must be called prior to any other calls in this class.
     *
     * The native library is expected to be be called "wolfssljni", and must be
     * on the system library search path.
     *
     * "wolfssljni" links against the wolfSSL native C library ("wolfssl"),
     * and for Windows compatibility "wolfssl" needs to be explicitly
     * loaded first here.
     *
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary() throws UnsatisfiedLinkError {

        int fipsLoaded = 0;

        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().contains("win")) {
            try {
                /* Default wolfCrypt FIPS library on Windows is compiled
                 * as "wolfssl-fips" by Visual Studio solution */
                System.loadLibrary("wolfssl-fips");
                fipsLoaded = 1;
            } catch (UnsatisfiedLinkError e) {
                /* wolfCrypt FIPS not available */
            }

            if (fipsLoaded == 0) {
                /* FIPS library not loaded, try normal libwolfssl */
                System.loadLibrary("wolfssl");
            }
        }

        /* Load wolfssljni library */
        System.loadLibrary("wolfssljni");
    }

    /**
     * Load JNI library with a specific name; must be called prior to any
     * other calls in this package.
     *
     * The native library needs to be located on the system library search
     * path.
     *
     * @param  libName name of native JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibrary(String libName) throws UnsatisfiedLinkError {
        System.loadLibrary(libName);
    }

    /**
     * Loads dynamic JNI library from a specific path; must be called prior to
     * any other calls in this package.
     *
     * This function gives the application more control over the exact native
     * library being loaded, as both WolfSSL.loadLibrary() and
     * WolfSSL.loadLibrary(String libName) search for a library on the system
     * library search path. This function allows the appliation to specify
     * a specific absolute path to the native library file to load, thus
     * guaranteeing the exact library loaded and helping to prevent against
     * malicious attackers from attempting to override the library being
     * loaded.
     *
     * @param  libPath complete path name to the native dynamic JNI library
     * @throws UnsatisfiedLinkError if the library is not found.
     */
    public static void loadLibraryAbsolute(String libPath)
        throws UnsatisfiedLinkError {
        System.load(libPath);
    }

    /* ----------------- generic static helper functions ---------------- */

    /**
     * Read a File into byte array.
     *
     * This method can't use the java.nio package since we have users
     * on Android API 24 which does not support java.nio.
     *
     * @param file File to read into byte array
     *
     * @return byte array representing input File, or null if file is null
     */
    protected static byte[] fileToBytes(File file)
        throws FileNotFoundException, IOException {

        int bytesRead = 0;
        long fileLen = 0;
        byte[] fileBytes = null;
        FileInputStream fis = null;

        if (file == null) {
            return null;
        }

        fileLen = file.length();
        if (fileLen == 0) {
            return new byte[0];
        }

        try {
            fis = new FileInputStream(file);
            if (fis != null) {
                fileBytes = new byte[(int)fileLen];

                bytesRead = fis.read(fileBytes);

                if (bytesRead != fileLen) {
                    throw new IOException("Unable to read entire file: " +
                        file.getAbsolutePath());
                }
            }
        } finally {
            if (fis != null) {
                fis.close();
            }
        }

        return fileBytes;
    }

    /* --------------- native feature detection functions --------------- */

    /**
     * Tests if TLS 1.0 has been compiled into the native wolfSSL library.
     * TLS 1.0 is disabled by default in native wolfSSL, unless the user
     * has configured wolfSSL with "--enable-tls10".
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean TLSv1Enabled();

    /**
     * Tests if TLS 1.1 has been compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean TLSv11Enabled();

    /**
     * Tests if TLS 1.2 has been compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean TLSv12Enabled();

    /**
     * Tests if TLS 1.3 has been compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean TLSv13Enabled();

    /**
     * Tests if SHA-1 is enabled in the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean ShaEnabled();

    /**
     * Tests if SHA-224 is enabled in the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha224Enabled();

    /**
     * Tests if SHA-256 is enabled in the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha256Enabled();

    /**
     * Tests if SHA-384 is enabled in the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha384Enabled();

    /**
     * Tests if SHA-512 is enabled in the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Sha512Enabled();

    /**
     * Tests if ECC support has been compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean EccEnabled();

    /**
     * Tests if RSA support has been compiled into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean RsaEnabled();

    /**
     * Tests if Curve25519/X25519 support has been compiled into the native
     * wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Curve25519Enabled();

    /**
     * Tests if Curve448/X448 support has been compiled into the native
     * wolfSSL library.
     *
     * @return true if enabled, otherwise false if not compiled in.
     */
    public static native boolean Curve448Enabled();

    /**
     * Tests if filesystem support has been compiled into the wolfSSL library.
     *
     * @return true if enabled, otherwise false if NO_FILESYSTEM has been
     *         defined.
     */
    public static native boolean FileSystemEnabled();

    /**
     * Tests if Certificate Signing Request (CSR) support has been compiled
     * into the native wolfSSL library.
     *
     * @return true if enabled, otherwise false if WOLFSSL_CERT_EXT not defined.
     */
    public static native boolean certReqEnabled();

    /**
     * Tests if native wolfSSL has been compiled with WOLFSSL_TRUST_PEER_CERT.
     *
     * @return true if enabled, otherwise false if WOLFSSL_TRUST_PEER_CERT
     *         has not been defined.
     */
    public static native boolean trustPeerCertEnabled();

    /**
     * Tests if native session ticket support has been compiled into wolfSSL
     * with HAVE_SESSION_TICKET.
     *
     * @return true if enabled, otherwise false if HAVE_SESSION_TICKET
     *         has not been defined.
     */
    public static native boolean sessionTicketEnabled();

    /**
     * Tests if native wolfSSL has been compiled with HAVE_SECRET_CALLBACK
     * default. If defined, will compile in APIs to support SSL/TLS secret
     * callback support.
     *
     * @return true if enabled, otherwise false if HAVE_SECRET_CALLBACK
     *         has not been defind.
     */
    public static native boolean secretCallbackEnabled();

    /* ---------------- native SSL/TLS version functions ---------------- */

    /**
     * Indicates that the application is a server and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public static final native long SSLv3_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * SSL 3.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     * @deprecated SSL 3.0 is now considered insecure.
     */
    @Deprecated
    public static final native long SSLv3_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.1 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.1 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_1_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_2_ClientMethod();

    /**
     * Indicates that the application will only support the TLS 1.3 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long TLSv1_3_Method();

    /**
     * Indicates that the application is a server and will only support the
     * TLS 1.3 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_3_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * TLS 1.3 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public final static native long TLSv1_3_ClientMethod();

    /**
     * Indicates that the application will only support the DTLS 1.0 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.0 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_ClientMethod();

    /**
     * Indicates that the application will only support the DTLS 1.2 protocol.
     * Application is side-independent at this time, and client/server side
     * will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_Method();

    /**
     * Indicates that the application is a server and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_ServerMethod();

    /**
     * Indicates that the application is a client and will only support the
     * DTLS 1.2 protocol.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long DTLSv1_2_ClientMethod();

    /**
     * Indicates that the application will use the highest possible SSL/TLS
     * version from SSL 3.0 up to TLS 1.2, but is side-independent at creation
     * time. Client/server side will be determined at connect/accept stage.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_Method();

    /**
     * Indicates that the application is a server and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_ServerMethod();

    /**
     * Indicates that the application is a client and will use the highest
     * possible SSL/TLS version from SSL 3.0 up to TLS 1.2.
     * This method allocates memory for and initializes a new native
     * WOLFSSL_METHOD structure to be used when creating the SSL/TLS
     * context with newContext().
     *
     * @return  A pointer to the created WOLFSSL_METHOD structure if
     *          successful, null on failure.
     * @see     WolfSSLContext#newContext(long)
     */
    public static final native long SSLv23_ClientMethod();

    /**
     * Converts an error code returned by getError() into a more human-
     * readable error string.
     * The maximum length of the returned string is 80 characters by
     * default, as defined by MAX_ERROR_SZ in the native wolfSSL
     * error.h header file.
     *
     * @param errNumber     error code returned by <code>getError()</code>
     * @return              output String containing human-readable error
     *                      string matching <code>errNumber</code>
     *                      on success. On failure, this method returns a
     *                      String with the appropriate failure reason.
     * @see                 WolfSSLSession#getError(long, int)
     */
    public static final native String getErrorString(long errNumber);

    /**
     * Un-initializes the wolfSSL library from further use.
     * Doesn't have to be called, though it will free any resources used by
     * the library.
     *
     * @return <code>SSL_SUCCESS</code> upon success, <code>BAD_MUTEX_ERROR
     *         </code> on mutex error.
     */
    public static final native int cleanup();

    /**
     * Turns on debug logging at runtime.
     * To enable logging at build time, use <b>--enable-debug</b> or define
     * <b>DEBUG_WOLFSSL</b>. Debugging must be enabled at build time in order
     * for the method to have any effect.
     *
     * @return  <code>SSL_SUCCESS</code> upon success. <code>NOT_COMPILED_IN
     *          </code> if logging isnt' enabled for this wolfSSL build.
     * @see     #debuggingOFF()
     * @see     #setLoggingCb(WolfSSLLoggingCallback)
     */
    public static final native int debuggingON();

    /**
     * Turns off runtime debug log messages.
     * If they're already off, no action is taken.
     *
     * @see #debuggingON()
     * @see #setLoggingCb(WolfSSLLoggingCallback)
     */
    public static final native void debuggingOFF();

    /**
     * Registers the callback to be used for Logging debug and trace
     * messages.
     *
     * @param cb    Callback to be used for logging debug messages
     * @return      <b><code>SSL_ERROR_NONE</code></b> upon success,
     *              <b><code>BAD_FUNC_ARG</code></b> if input is null,
     *              <b><code>NOT_COMPILED_IN</code></b> if wolfSSL was not
     *              compiled with debugging support enabled.
     * @see         #debuggingON()
     * @see         #debuggingOFF()
     */
    public static final native int setLoggingCb(WolfSSLLoggingCallback cb);

    /**
     * Registers the callback to be used for wolfCrypt FIPS verifyCore error.
     * This method is a NOOP if called when not using a wolfCrypt FIPS
     * library.
     *
     * @param cb    Callback to be used for wolfCrypt FIPS verifyCore errors
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>NOT_COMPILED_IN</code></b> if not using wolfCrypt
     *              FIPS library distribution, or negative on error.
     */
    public static final native int setFIPSCb(WolfSSLFIPSErrorCallback cb);


    /**
     * Returns the current verifyCore hash from wolfCrypt FIPS, from
     * native wolfcrypt/src/fips_test.c, verifyCore[] array.
     *
     * NOTE: this method returns NULL if not used with a wolfCrypt FIPS
     * library.
     *
     * @return current verifyCore hash from wolfCrypt FIPS, or NULL
     *         if called when not using a wolfCrypt FIPS library.
     */
    public static final native String getWolfCryptFIPSCoreHash();

    /**
     * Persists session cache to memory buffer.
     * This method can be used to persist the current session cache to a
     * memory buffer for storage. The cache can be loaded back into wolfSSL
     * using the corresponding <code>memrestoreSessionCache()</code> method.
     *
     * @param mem   buffer to store session cache in
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> on success,
     *              <b><code>SSL_FAILURE</code></b> on general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small to store the session cache in,
     *              <b><code>BAD_MUTEX_ERROR</code></b> if the session cache
     *              mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memsaveSessionCache(byte[] mem, int sz);

    /**
     * Restores the persistant session cache from memory buffer.
     * This function restores a session cache that was previously saved to
     * a memory buffer.
     *
     * @param mem   buffer containing persistant session cache to be restored
     * @param sz    size of the input buffer, <b>mem</b>
     * @return      <b><code>SSL_SUCCESS</code></b> upon success,
     *              <b><code>SSL_FAILURE</code></b> upon general failure,
     *              <b><code>BUFFER_E</code></b> if the memory buffer is too
     *              small, <b><code>CACHE_MATCH_ERROR</code></b> if the
     *              session cache header match failed and there were
     *              differences in how the cache and the current library
     *              are configured, <b><code>BAD_MUTEX_ERROR</code></b>
     *              if the session cache mutex lock failed,
     *              <b><code>BAD_FUNC_ARG</code></b> if invalid parameters are
     *              used.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #getSessionCacheMemsize()
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int memrestoreSessionCache(byte[] mem, int sz);

    /**
     * Gets how big the session cache save buffer needs to be.
     * Use this method to determine how large the buffer needs to be to
     * store the persistant session cache into memory.
     *
     * @return      size, in bytes, of how large the output buffer should be
     *              to store the session cache into memory.
     * @see         #memsaveSessionCache(byte[], int)
     * @see         #memrestoreSessionCache(byte[], int)
     * @see         WolfSSLContext#memsaveCertCache(long, byte[], int, int[])
     * @see         WolfSSLContext#memrestoreCertCache(long, byte[], int)
     * @see         WolfSSLContext#getCertCacheMemsize(long)
     */
    public static native int getSessionCacheMemsize();

    /**
     * Strips off PKCS#8 header from byte array.
     * This function starts reading the input array for a PKCS#8 header,
     * beginning at input offset, idx. If found, it returns the offset of
     * the inner traditional data.
     *
     * @param in  input buffer containing PKCS#8 formatted key
     * @param idx index/offset into input array to begin reading
     * @param sz  size of input array
     * @return    offset where the traditional key begins, or negative on
     *            failure.
     */
    public static native int getPkcs8TraditionalOffset(byte[] in, long idx,
        long sz);

    /**
     * Returns the DER-encoded form of the certificate pointed to by
     * x509.
     *
     * @param x509      pointer (long) to a native WOLFSSL_X509 object. This
     *                  objects represents an X.509 certificate.
     * @return          DER-encoded certificate or
     *                  <code>null</code> if the input buffer is null.
     *
     */
    public static native byte[] x509_getDer(long x509);

    /**
     * Returns the wolfSSL max HMAC digest size.
     * Specifically, returns the value of the native wolfSSL
     * MAX_DIGEST_SIZE define.
     *
     * @return  value of native MAX_DIGEST_SIZE define
     */
    public static native int getHmacMaxSize();

    /**
     * Return the wolfSSL library vesrion number in hex.
     *
     * Wrapper around native wolfSSL_lib_version_hex()
     *
     * @return wolfSSL native library version hex value
     */
    public static native long getLibVersionHex();

    /**
     * Returns the enabled cipher suites for native wolfSSL.
     *
     * @return array of cipher suite Strings
     */
    public static String[] getCiphers() {

        String cipherSuites = getEnabledCipherSuites();
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Gets a list of all cipher suites supported by native wolfSSL and
     * uses the format TLS_*. This list may not be in priority order. If
     * priority order is desired, see getCiphersAvailableIana().
     * @return list of all cipher suites supported
     */
    public static String[] getCiphersIana() {
        String cipherSuites = getEnabledCipherSuitesIana();
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Gets a list of all cipher suites available for current native wolfSSL
     * configuration and selected protocol level. In the format TLS_*.
     *
     * @param version protocol version for which to get cipher suites.
     * @return list of cipher suites.
     */
    public static String[] getCiphersAvailableIana(TLS_VERSION version) {
        /* passing Enum as ordinal to JNI layer, see com_wolfssl_WolfSSL.c */
        String cipherSuites = getAvailableCipherSuitesIana(version.ordinal());
        if (cipherSuites == null)
            return null;

        return cipherSuites.split(":");
    }

    /**
     * Register native wolfSSL crypto callback function. Currently requires
     * modification to native JNI code to write/implement correct native
     * crypto callback function implementation.
     *
     * Note that this API only allows one devId to be set. Users who need
     * support for multiple devId's and callbacks, please contact
     * support@wolfssl.com to open a feature request.
     *
     * See native/com_wolfssl_WolfSSL.c
     *
     * @param devId device ID to register crypto callback for
     *
     * @return 0 on success, negative on error
     */
    public static int cryptoCbRegisterDevice(int devId) {

        return wc_CryptoCb_RegisterDevice(devId);
    }

    /**
     * Unregister native wolfSSL crypto callback function.
     * @param devId device ID to unregister
     *
     * @return 0 on success, negative on error.
     */
    public static int cryptoCbUnRegisterDevice(int devId) {

        wc_CryptoCb_UnRegisterDevice(devId);

        return 0;
    }

    /* ------------------------- isEnabled methods -------------------------- */

    /**
     * Checks if CRL support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRL();

    /**
     * Checks if CRL Monitor support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledCRLMonitor();

    /**
     * Checks if OCSP support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledOCSP();

    /**
     * Checks if PSK support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPSK();

    /**
     * Checks if DTLS support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledDTLS();

    /**
     * Checks if Atomic User support is enabled in wolfSSL native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledAtomicUser();

    /**
     * Checks if Public Key Callback support is enabled in wolfSSL
     * native library.
     *
     * @return 1 if enabled, 0 if not compiled in
     */
    public static native int isEnabledPKCallbacks();

    /**
     * Checks which protocols where built into wolfSSL
     *
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocols();

    /**
     * Checks which protocols where built into wolfSSL with Mask
     *
     * @param mask flags prohibiting TLS version (i.e. SSL_OP_NO_xxx)
     * @return an array of Strings for supported protocols
     */
    public static native String[] getProtocolsMask(long mask);

    /* ----------------------- native helper methods ------------------------ */

    /**
     * Return native system errno value.
     *
     * Some native system calls, such as select() will set errno when an
     * error is encountered. This JNI method is a simple getter to retrive
     * the current system errno value.
     *
     * If on Windows, this will return 0 (no errno support on Windows)
     *
     * @return System native errno value
     */
    public static native int getErrno();

    /**
     * Gets the internal wolfSSL named group enum matching provided string.
     *
     * Returned enum values are in Named Groups section above and come from
     * native ssl.h "Named Groups" enum.
     *
     * @param curveName String representation of ECC curve
     * @return Native wolfSSL Named Groups enum value which maps to input
     *         String, or WolfSSL.WOLFSSL_NAMED_GROUP_INVALID if curve
     *         String not supported.
     */
    protected static int getNamedGroupFromString(String curveName) {

        switch (curveName) {
            case "sect163k1":
                return WolfSSL.WOLFSSL_ECC_SECT163K1;
            case "sect163r1":
                return WolfSSL.WOLFSSL_ECC_SECT163R1;
            case "sect163r2":
                return WolfSSL.WOLFSSL_ECC_SECT163R2;
            case "sect193r1":
                return WolfSSL.WOLFSSL_ECC_SECT193R1;
            case "sect193r2":
                return WolfSSL.WOLFSSL_ECC_SECT193R2;
            case "sect233k1":
                return WolfSSL.WOLFSSL_ECC_SECT233K1;
            case "sect233r1":
                return WolfSSL.WOLFSSL_ECC_SECT233R1;
            case "sect239k1":
                return WolfSSL.WOLFSSL_ECC_SECT239K1;
            case "sect283k1":
                return WolfSSL.WOLFSSL_ECC_SECT283K1;
            case "sect283r1":
                return WolfSSL.WOLFSSL_ECC_SECT283R1;
            case "sect409k1":
                return WolfSSL.WOLFSSL_ECC_SECT409K1;
            case "sect409r1":
                return WolfSSL.WOLFSSL_ECC_SECT409R1;
            case "sect571k1":
                return WolfSSL.WOLFSSL_ECC_SECT571K1;
            case "sect571r1":
                return WolfSSL.WOLFSSL_ECC_SECT571R1;
            case "secp160k1":
                return WolfSSL.WOLFSSL_ECC_SECP160K1;
            case "secp160r1":
                return WolfSSL.WOLFSSL_ECC_SECP160R1;
            case "secp160r2":
                return WolfSSL.WOLFSSL_ECC_SECP160R2;
            case "secp192k1":
                return WolfSSL.WOLFSSL_ECC_SECP192K1;
            case "secp192r1":
                return WolfSSL.WOLFSSL_ECC_SECP192R1;
            case "secp224k1":
                return WolfSSL.WOLFSSL_ECC_SECP224K1;
            case "secp224r1":
                return WolfSSL.WOLFSSL_ECC_SECP224R1;
            case "secp256k1":
                return WolfSSL.WOLFSSL_ECC_SECP256K1;
            case "secp256r1":
                return WolfSSL.WOLFSSL_ECC_SECP256R1;
            case "secp384r1":
                return WolfSSL.WOLFSSL_ECC_SECP384R1;
            case "secp521r1":
                return WolfSSL.WOLFSSL_ECC_SECP521R1;
            case "brainpoolP256r1":
                return WolfSSL.WOLFSSL_ECC_BRAINPOOLP256R1;
            case "brainpoolP384r1":
                return WolfSSL.WOLFSSL_ECC_BRAINPOOLP384R1;
            case "brainpoolP512r1":
                return WolfSSL.WOLFSSL_ECC_BRAINPOOLP512R1;
            case "X25519":
            case "x25519":
                return WolfSSL.WOLFSSL_ECC_X25519;
            case "X448":
            case "x448":
                return WolfSSL.WOLFSSL_ECC_X448;
            case "sm2P256v1":
                return WolfSSL.WOLFSSL_ECC_SM2P256V1;
            case "ffdhe2048":
                return WolfSSL.WOLFSSL_FFDHE_2048;
            case "ffdhe3072":
                return WolfSSL.WOLFSSL_FFDHE_3072;
            case "ffdhe4096":
                return WolfSSL.WOLFSSL_FFDHE_4096;
            case "ffdhe6144":
                return WolfSSL.WOLFSSL_FFDHE_6144;
            case "ffdhe8192":
                return WolfSSL.WOLFSSL_FFDHE_8192;
            default:
                return WolfSSL.WOLFSSL_NAMED_GROUP_INVALID;

        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        synchronized(cleanupLock) {
            if (this.active == true) {
                /* reset logging callback before calling cleanup() */
                this.setLoggingCb(null);

                /* free resources, set state */
                this.cleanup();
                this.active = false;
            }
        }
        super.finalize();
    }

} /* end WolfSSL */

