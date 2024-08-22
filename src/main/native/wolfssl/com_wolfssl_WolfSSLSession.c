/* com_wolfssl_WolfSSLSession.c
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

#include <stdio.h>
#include <stdint.h>

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#ifndef USE_WINDOWS_API
    #include <sys/time.h>
    #include <arpa/inet.h>
    #include <sys/errno.h>
#endif
#ifdef WOLFJNI_USE_IO_SELECT
    #include <sys/select.h>
#else
    #include <poll.h>
#endif

#ifndef WOLFSSL_JNI_DEFAULT_PEEK_TIMEOUT
    /* Default wolfSSL_peek() timeout for wolfSSL_get_session(), ms */
    #define WOLFSSL_JNI_DEFAULT_PEEK_TIMEOUT 2000
#endif

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSL.h"

/* custom I/O native fn prototypes */
int NativeSSLIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);
int NativeSSLIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx);

/* ALPN select native callback prototype */
int NativeALPNSelectCb(WOLFSSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg);

/* TLS 1.3 secret native callback prototype */
int NativeTls13SecretCb(WOLFSSL *ssl, int id, const unsigned char* secret,
    int secretSz, void* ctx);

#ifdef HAVE_CRL
/* global object refs for CRL callback */
static jobject g_crlCbIfaceObj;
#endif

/* Data used per-WOLFSSL session that needs to be stored across native
 * function calls. Stored inside WOLFSSL app data, set with
 * wolfSSL_set_app_data(), retrieved with wolfSSL_get_app_data().
 * Global callback objects are created with NewGlobalRef(), then freed
 * inside freeSSL() with DeleteGlobalRef(). */
typedef struct SSLAppData {
    wolfSSL_Mutex* jniSessLock;      /* WOLFSSL session lock */
    jobject* g_verifySSLCbIfaceObj;  /* Java verify callback [global ref] */
} SSLAppData;

/* custom native fn prototypes */
void NativeMissingCRLCallback(const char* url);
int  NativeSSLVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store);

int NativeSSLVerifyCallback(int preverify_ok, WOLFSSL_X509_STORE_CTX* store)
{
    JNIEnv*   jenv;
    jint      vmret  = 0;
    jint      retval = -1;
    jclass    excClass;
    jclass    verifyClass = NULL;
    jmethodID verifyMethod;
    jobjectRefType refcheck;
    SSLAppData* appData;            /* WOLFSSL app data, stored verify cb obj */
    jobject* g_verifySSLCbIfaceObj;  /* Global jobject, stored in app data */

    if (!g_vm) {
        /* we can't throw an exception yet, so just return 0 (failure) */
        return 0;
    }

    /* get JNIEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return -101;    /* failed to attach JNIEnv to thread */
        }
    } else if (vmret != JNI_OK) {
        return -102;        /* unable to get JNIEnv from JavaVM */
    }

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if( (*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -103;
    }

    /* get app data to retrieve stored Java jobject callback object */
    appData = (SSLAppData*)wolfSSL_get_app_data(
                wolfSSL_X509_STORE_CTX_get_ex_data(store, 0));
    if (appData == NULL) {
        printf("Error getting app data from WOLFSSL\n");
        return -105;
    }

    /* get global Java verify callback object */
    g_verifySSLCbIfaceObj = appData->g_verifySSLCbIfaceObj;
    if (g_verifySSLCbIfaceObj == NULL || *g_verifySSLCbIfaceObj == NULL) {
        printf("Error getting g_verifySSLCbIfaceObj from appData\n");
        return -106;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, *g_verifySSLCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLVerifyCallback class from global object ref */
        verifyClass = (*jenv)->GetObjectClass(jenv, *g_verifySSLCbIfaceObj);
        if (!verifyClass) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLVerifyCallback class reference");
            return -107;
        }

        verifyMethod = (*jenv)->GetMethodID(jenv, verifyClass,
                                            "verifyCallback", "(IJ)I");
        if (verifyMethod == 0) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Error getting verifyCallback method from JNI");
            return -108;
        }

        retval = (*jenv)->CallIntMethod(jenv, *g_verifySSLCbIfaceObj,
                verifyMethod, preverify_ok, (jlong)(uintptr_t)store);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* exception occurred on the Java side during method call */
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return -109;
        }

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeSSLVerifyCallback");
        return -1;
    }

    return retval;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_newSSL
  (JNIEnv* jenv, jobject jcl, jlong ctx)
{
    int ret;
    jlong sslPtr = 0;
    jobject* g_cachedSSLObj = NULL;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* wolfSSL java caller checks for null pointer */
    sslPtr = (jlong)(uintptr_t)wolfSSL_new((WOLFSSL_CTX*)(uintptr_t)ctx);

    if (sslPtr != 0) {
        /* create global reference to WolfSSLSession jobject */
        g_cachedSSLObj = (jobject*)XMALLOC(sizeof(jobject), NULL,
                                        DYNAMIC_TYPE_TMP_BUFFER);
        if (g_cachedSSLObj == NULL) {
            printf("error mallocing memory in newSSL\n");
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        *g_cachedSSLObj = (*jenv)->NewGlobalRef(jenv, jcl);
        if (*g_cachedSSLObj == NULL) {
            printf("error storing global WolfSSLSession object\n");
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        appData = (SSLAppData*)XMALLOC(sizeof(SSLAppData), NULL,
                                       DYNAMIC_TYPE_TMP_BUFFER);
        if (appData == NULL) {
            printf("error allocating memory in newSSL for SSLAppData\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
        XMEMSET(appData, 0, sizeof(SSLAppData));

        /* store mutex lock in SSL app data, used for I/O and session lock.
         * This is freed in freeSSL. */
        jniSessLock = (wolfSSL_Mutex*)XMALLOC(sizeof(wolfSSL_Mutex), NULL,
                                              DYNAMIC_TYPE_TMP_BUFFER);
        if (!jniSessLock) {
            printf("error mallocing memory in newSSL for jniSessLock\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        wc_InitMutex(jniSessLock);
        appData->jniSessLock = jniSessLock;

        /* cache associated WolfSSLSession jobject in native WOLFSSL */
        ret = wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)sslPtr, g_cachedSSLObj);
        if (ret != SSL_SUCCESS) {
            printf("error storing jobject in wolfSSL native session\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }

        /* cache SSLAppData into native WOLFSSL */
        if (wolfSSL_set_app_data(
                (WOLFSSL*)(uintptr_t)sslPtr, appData) != SSL_SUCCESS) {
            printf("error setting WOLFSSL app data in newSSL\n");
            (*jenv)->DeleteGlobalRef(jenv, *g_cachedSSLObj);
            XFREE(jniSessLock, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            wolfSSL_set_jobject((WOLFSSL*)(uintptr_t)sslPtr, NULL);
            wolfSSL_free((WOLFSSL*)(uintptr_t)sslPtr);
            return SSL_FAILURE;
        }
    }

    return sslPtr;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setFd(JNIEnv* jenv,
    jobject jcl, jlong sslPtr, jobject jsock, jint type)
{
    int fd;
    int ret = SSL_SUCCESS;
    jclass jcls;
    jfieldID fid;
    jobject impl;
    jobject fdesc;
#ifdef USE_WINDOWS_API
    unsigned long blocking = 0;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || jsock == NULL) {
        printf("Error: bad function args, native setFd() wrapper\n");
        return SSL_FAILURE;
    }

    /* get SocketImpl (type 1) or DatagramSocketImpl (2) from Java Socket */
    jcls = (*jenv)->GetObjectClass(jenv, jsock);
    if (type == 1) {
        /* Get SocketImpl field 'impl' from Socket class */
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl", "Ljava/net/SocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            printf("Error: Failed to get SocketImpl impl FieldID\n");
            return SSL_FAILURE;
        }
        /* Get SocketImpl 'impl' object */
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);

        /* SocketImpl object may hold a delegate object inside on
         * some Java versions. Delegate SocketImpl is held inside 'impl'
         * object in field 'delegate'. Here we try to get the 'delegate'
         * field ID. If NULL, there is no 'delegate' member and we fall back
         * to using 'impl' directly. */
        jcls = (*jenv)->GetObjectClass(jenv, impl);
        fid = (*jenv)->GetFieldID(jenv, jcls, "delegate", "Ljava/net/SocketImpl;");
        if (fid != NULL) {
            /* delegate field exists, try to get object */
            impl = (*jenv)->GetObjectField(jenv, impl, fid);
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
                /* Exception while getting delegate field, but does exist */
                printf("Error: Exception while getting SocketImpl delegate\n");
                return SSL_FAILURE;
            }
        } else {
            /* if delegate field does not exist, can cause NoSuchFieldError
             * exception. Clear out before continuing, but don't
             * print exception description (we expect it to happen). */
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionClear(jenv);
            }
        }

    } else if (type == 2) {
        fid = (*jenv)->GetFieldID(jenv, jcls, "impl",
                "Ljava/net/DatagramSocketImpl;");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            printf("Error: Exception while getting DatagramSocketImpl "
                   "impl FieldID\n");
            return SSL_FAILURE;
        }
        impl = (*jenv)->GetObjectField(jenv, jsock, fid);
    } else {
        printf("Invalid Socket class type, not supported\n");
        return SSL_FAILURE; /* invalid class type */
    }

    if (impl == NULL) {
        printf("Error: SocketImpl impl is NULL! Not valid\n");
        return SSL_FAILURE;
    }

    /* get FileDescriptor from SocketImpl */
    jcls = (*jenv)->GetObjectClass(jenv, impl);
    fid = (*jenv)->GetFieldID(jenv, jcls, "fd", "Ljava/io/FileDescriptor;");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        printf("Error: Exception while getting FileDescriptor fd FieldID\n");
        return SSL_FAILURE;
    }

    fdesc = (*jenv)->GetObjectField(jenv, impl, fid);
    if (fdesc == NULL) {
        printf("Info: FileDescriptor fd object is NULL!\n");
        return SSL_FAILURE;
    }

    /* get fd from FileDescriptor */
    jcls = (*jenv)->GetObjectClass(jenv, fdesc);
#ifdef __ANDROID__
    fid = (*jenv)->GetFieldID(jenv, jcls, "descriptor", "I");
#else
    fid = (*jenv)->GetFieldID(jenv, jcls, "fd", "I");
#endif
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        printf("Error: Exception while getting fd/descriptor FieldID\n");
        return SSL_FAILURE;
    }

    if (jcls == NULL || fid == NULL) {
        printf("Error: jcls or fid NULL while getting fd/descriptor\n");
        return SSL_FAILURE;
    }

    fd = (*jenv)->GetIntField(jenv, fdesc, fid);

    /* set socket to non-blocking so we can use select() to detect
     * WANT_READ / WANT_WRITE */
#ifdef USE_WINDOWS_API
    ret = ioctlsocket(fd, FIONBIO, &blocking);
    if (ret == SOCKET_ERROR) {
        ret = SSL_FAILURE;
    }
    else {
        ret = SSL_SUCCESS;
    }
#else
    ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    if (ret < 0) {
        ret = SSL_FAILURE;
    }
    else {
        ret = SSL_SUCCESS;
    }
#endif

    if (ret == SSL_SUCCESS) {
        ret = wolfSSL_set_fd(ssl, fd);
    }

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* certFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    certFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_file(ssl, certFile, (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, certFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* keyFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    keyFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_PrivateKey_file(ssl, keyFile, (int)format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, keyFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file)
{
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    jint ret = 0;
    const char* chainFile;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    chainFile = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = (jint) wolfSSL_use_certificate_chain_file(ssl, chainFile);

    (*jenv)->ReleaseStringUTFChars(jenv, file, chainFile);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint nonblock)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in setUsingNonblock");
    }

    wolfSSL_set_using_nonblock(ssl, nonblock);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getUsingNonblock
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getUsingNonblock");
    }

    return wolfSSL_get_using_nonblock(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getFd
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in getFd");
        return 0;
    }

    return wolfSSL_get_fd(ssl);
}

/* enum values used in socketSelect() and socketPoll(). Some of these
 * values are also duplicated in WolfSSL.java for access from Java classes.
 * If updated here, make sure to update in WolfSSL.java too. */
enum {
    WOLFJNI_IO_EVENT_FAIL            = -10,
    WOLFJNI_IO_EVENT_TIMEOUT         = -11,
    WOLFJNI_IO_EVENT_RECV_READY      = -12,
    WOLFJNI_IO_EVENT_SEND_READY      = -13,
    WOLFJNI_IO_EVENT_ERROR           = -14,
    WOLFJNI_IO_EVENT_FD_CLOSED       = -15,
    WOLFJNI_IO_EVENT_POLLHUP         = -16,
    WOLFJNI_IO_EVENT_INVALID_TIMEOUT = -17
};

#ifdef WOLFJNI_USE_IO_SELECT

/* Perform a select() call on the underlying socket to wait for socket to be
 * ready for read/write, or timeout. Note that we explicitly set the underlying
 * socket descriptor to non-blocking.
 *
 * NOTE: the FD_ISSET macro behavior is undefined if the descriptor value is
 *       less than 0 or greater than or equal to FD_SETSIZE (1024 by default).
 *
 * On a Java Socket, a timeout of 0 is an infinite timeout. Greater than zero
 * is a timeout in milliseconds. Negative timeout is invalid and not supported.
 * For select(), a non-NULL timeval struct specifies maximum timeout to wait,
 * a NULL timeval struct is an infinite timeout. A zero-valued timeval struct
 * will return immediately (no timeout).
 *
 * @param sockfd     socket descriptor to select()
 * @param timeout_ms timeout in milliseconds. 0 indicates infinite timeout, to
 *                   match Java timeout behavior. Negative timeout not
 *                   supported, since not supported on Java Socket.
 * @param rx         set to 1 to monitor readability on socket descriptor,
 *                   otherwise 0 to monitor writability
 *
 * @return possible return values are:
 *         WOLFJNI_IO_EVENT_FAIL
 *         WOLFJNI_IO_EVENT_ERROR
 *         WOLFJNI_IO_EVENT_TIMEOUT
 *         WOLFJNI_IO_EVENT_RECV_READY
 *         WOLFJNI_IO_EVENT_SEND_READY
 *         WOLFJNI_IO_EVENT_INVALID_TIMEOUT
 */
static int socketSelect(int sockfd, int timeout_ms, int rx)
{
    fd_set fds, errfds;
    fd_set* recvfds = NULL;
    fd_set* sendfds = NULL;
    int nfds = sockfd + 1;
    int result = 0;
    struct timeval timeout;

    /* Java Socket does not support negative timeouts, sanitize */
    if (timeout_ms < 0) {
        return WOLFJNI_IO_EVENT_INVALID_TIMEOUT;
    }

#ifndef USE_WINDOWS_API
    do {
#endif
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        FD_ZERO(&fds);
        FD_SET(sockfd, &fds);
        FD_ZERO(&errfds);
        FD_SET(sockfd, &errfds);

        if (rx) {
            recvfds = &fds;
        } else {
            sendfds = &fds;
        }

        if (timeout_ms == 0) {
            result = select(nfds, recvfds, sendfds, &errfds, NULL);
        } else {
            result = select(nfds, recvfds, sendfds, &errfds, &timeout);
        }

        if (result == 0) {
            return WOLFJNI_IO_EVENT_TIMEOUT;
        } else if (result > 0) {
            if (FD_ISSET(sockfd, &fds)) {
                if (rx) {
                    return WOLFJNI_IO_EVENT_RECV_READY;
                } else {
                    return WOLFJNI_IO_EVENT_SEND_READY;
                }
            } else if (FD_ISSET(sockfd, &errfds)) {
                return WOLFJNI_IO_EVENT_ERROR;
            }
        }

#ifndef USE_WINDOWS_API
    } while ((result == -1) && ((errno == EINTR) || (errno == EAGAIN)));
#endif

    /* Return on error, unless errno EINTR or EAGAIN, try again above */
    return WOLFJNI_IO_EVENT_FAIL;
}

#else /* !WOLFJNI_USE_IO_SELECT */

/* Perform poll() on underlying socket descriptor to wait for socket to be
 * ready for read/write, or timeout. Note that we are explicitly setting
 * the underlying descriptor to non-blocking.
 *
 * On a Java Socket, a timeout of 0 is an infinite timeout. Greater than zero
 * is a timeout in milliseconds. Negative timeout is invalid and not supported.
 * For poll(), timeout greater than 0 specifies max timeout in milliseconds,
 * zero timeout will return immediately (no timeout), and -1 will block
 * indefinitely.
 *
 * @param sockfd     socket descriptor to poll()
 * @param timeout_ms timeout in milliseconds. 0 indicates infinite timeout, to
 *                   match Java timeout behavior. Negative timeout not
 *                   supported, since not supported on Java Socket.
 * @param rx         set to 1 to monitor readability on socket descriptor,
 *                   otherwise 0 to ignore readability events
 * @param tx         set to 1 to monitor writability on socket descriptor,
 *                   otherwise 0 to ignore writability events
 *
 * @return possible return values are:
 *         WOLFJNI_IO_EVENT_FAIL
 *         WOLFJNI_IO_EVENT_ERROR
 *         WOLFJNI_IO_EVENT_TIMEOUT
 *         WOLFJNI_IO_EVENT_RECV_READY
 *         WOLFJNI_IO_EVENT_SEND_READY
 *         WOLFJNI_IO_EVENT_FD_CLOSED
 *         WOLFJNI_IO_EVENT_POLLHUP
 *         WOLFJNI_IO_EVENT_INVALID_TIMEOUT
 */
static int socketPoll(int sockfd, int timeout_ms, int rx, int tx)
{
    int ret;
    int timeout;
    struct pollfd fds[1];

    /* Sanitize timeout and convert from Java to poll() expectations */
    timeout = timeout_ms;
    if (timeout < 0) {
        return WOLFJNI_IO_EVENT_INVALID_TIMEOUT;
    } else if (timeout == 0) {
        timeout = -1;
    }

    fds[0].fd = sockfd;
    fds[0].events = 0;
    if (tx) {
        fds[0].events |= POLLOUT;
    }
    if (rx) {
        fds[0].events |= POLLIN;
    }

    do {
        ret = poll(fds, 1, timeout);
        if (ret == 0) {
            return WOLFJNI_IO_EVENT_TIMEOUT;

        } else if (ret > 0) {
            if (fds[0].revents & POLLIN ||
                fds[0].revents & POLLPRI) {         /* read possible */
                return WOLFJNI_IO_EVENT_RECV_READY;

            } else if (fds[0].revents & POLLOUT) {  /* write possible */
                return WOLFJNI_IO_EVENT_SEND_READY;

            } else if (fds[0].revents & POLLNVAL) { /* fd not open */
                return WOLFJNI_IO_EVENT_FD_CLOSED;

            } else if (fds[0].revents & POLLERR) {  /* exceptional error */
                return WOLFJNI_IO_EVENT_ERROR;

            } else if (fds[0].revents & POLLHUP) {  /* sock disconnected */
                return WOLFJNI_IO_EVENT_POLLHUP;
            }
        }

    } while ((ret == -1) && ((errno == EINTR) || (errno == EAGAIN)));

    return WOLFJNI_IO_EVENT_FAIL;
}

#endif /* WOLFJNI_USE_IO_SELECT */

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_connect
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint timeout)
{
    int ret = 0, err = 0, sockfd = 0;
    int pollRx = 0;
    int pollTx = 0;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return WOLFSSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_connect(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            if (err == SSL_ERROR_WANT_READ) {
                pollRx = 1;
            }
            else if (err == SSL_ERROR_WANT_WRITE) {
                pollTx = 1;
            }

        #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
            ret = socketSelect(sockfd, (int)timeout, pollRx);
        #else
            ret = socketPoll(sockfd, (int)timeout, pollRx, pollTx);
        #endif
            if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                /* I/O ready, continue handshake and try again */
                continue;
            } else if (ret == WOLFJNI_IO_EVENT_TIMEOUT ||
                       ret == WOLFJNI_IO_EVENT_FD_CLOSED ||
                       ret == WOLFJNI_IO_EVENT_ERROR ||
                       ret == WOLFJNI_IO_EVENT_POLLHUP ||
                       ret == WOLFJNI_IO_EVENT_FAIL) {
                /* Java will throw SocketTimeoutException or SocketException */
                break;
            } else {
                /* error */
                ret = SSL_FAILURE;
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_write
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray raw, jint offset,
   jint length, jint timeout)
{
    byte* data = NULL;
    int ret = SSL_FAILURE, err, sockfd;
    int pollRx = 0;
    int pollTx = 0;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || raw == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((offset >= 0) && (length >= 0)) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }

        /* get session mutex from SSL app data */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return WOLFSSL_FAILURE;
        }

        jniSessLock = appData->jniSessLock;
        if (jniSessLock == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return SSL_FAILURE;
        }

        do {

            /* lock mutex around session I/O before write attempt */
            if (wc_LockMutex(jniSessLock) != 0) {
                ret = WOLFSSL_FAILURE;
                break;
            }

            ret = wolfSSL_write(ssl, data + offset, length);
            err = wolfSSL_get_error(ssl, ret);

            /* unlock mutex around session I/O after write attempt */
            if (wc_UnLockMutex(jniSessLock) != 0) {
                ret = WOLFSSL_FAILURE;
                break;
            }

            if (ret >= 0) /* return if it is success */
                break;

            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {

                sockfd = wolfSSL_get_fd(ssl);
                if (sockfd == -1) {
                    /* For I/O that does not use sockets, sockfd may be -1,
                     * skip try to call select() */
                    break;
                }

                if (err == SSL_ERROR_WANT_READ) {
                    pollRx = 1;
                }
                else if (err == SSL_ERROR_WANT_WRITE) {
                    pollTx = 1;
                }

            #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
                ret = socketSelect(sockfd, (int)timeout, pollRx);
            #else
                ret = socketPoll(sockfd, (int)timeout, pollRx, pollTx);
            #endif
                if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                    (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                    /* loop around and try wolfSSL_write() again */
                    continue;
                } else if (ret == WOLFJNI_IO_EVENT_TIMEOUT ||
                           ret == WOLFJNI_IO_EVENT_FD_CLOSED ||
                           ret == WOLFJNI_IO_EVENT_ERROR ||
                           ret == WOLFJNI_IO_EVENT_POLLHUP ||
                           ret == WOLFJNI_IO_EVENT_FAIL) {
                    /* Java will throw SocketTimeoutException or
                     * SocketException */
                    break;
                } else {
                    /* error */
                    ret = WOLFSSL_FAILURE;
                    break;
                }
            }

        } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, JNI_ABORT);

        return ret;

    } else {
        return SSL_FAILURE;
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_read
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray raw, jint offset,
   jint length, jint timeout)
{
    byte* data = NULL;
    int size = 0, ret, err, sockfd;
    int pollRx = 0;
    int pollTx = 0;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || raw == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((offset >= 0) && (length >= 0)) {
        data = (byte*)(*jenv)->GetByteArrayElements(jenv, raw, NULL);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }

        /* get session mutex from SSL app data */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return WOLFSSL_FAILURE;
        }

        jniSessLock = appData->jniSessLock;
        if (jniSessLock == NULL) {
            (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data,
                    JNI_ABORT);
            return WOLFSSL_FAILURE;
        }

        do {
            /* lock mutex around session I/O before read attempt */
            if (wc_LockMutex(jniSessLock) != 0) {
                size = WOLFSSL_FAILURE;
                break;
            }

            size = wolfSSL_read(ssl, data + offset, length);
            err = wolfSSL_get_error(ssl, size);

            /* unlock mutex around session I/O after read attempt */
            if (wc_UnLockMutex(jniSessLock) != 0) {
                size = WOLFSSL_FAILURE;
                break;
            }

            if (size < 0 && ((err == SSL_ERROR_WANT_READ) || \
                             (err == SSL_ERROR_WANT_WRITE))) {

                sockfd = wolfSSL_get_fd(ssl);
                if (sockfd == -1) {
                    /* For I/O that does not use sockets, sockfd may be -1,
                     * skip try to call select() */
                    break;
                }

                if (err == SSL_ERROR_WANT_READ) {
                    pollRx = 1;
                }
                else if (err == SSL_ERROR_WANT_WRITE) {
                    pollTx = 1;
                }

            #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
                ret = socketSelect(sockfd, (int)timeout, pollRx);
            #else
                ret = socketPoll(sockfd, (int)timeout, pollRx, pollTx);
            #endif
                if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                    (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                    /* loop around and try wolfSSL_read() again */
                    continue;
                } else {
                    /* Java will throw SocketTimeoutException or
                    * SocketException if ret equals
                    * WOLFJNI_IO_EVENT_TIMEOUT, WOLFJNI_IO_EVENT_FD_CLOSED
                    * WOLFJNI_IO_EVENT_ERROR, WOLFJNI_IO_EVENT_POLLHUP or
                    * WOLFJNI_IO_EVENT_FAIL */
                    size = ret;
                    break;
                }
            }

        } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

        /* JNI_COMMIT commits the data but does not free the local array
         * 0 is used here to both commit and free */
        (*jenv)->ReleaseByteArrayElements(jenv, raw, (jbyte*)data, 0);
    }

    return size;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_accept
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint timeout)
{
    int ret = 0, err, sockfd;
    int pollRx = 0;
    int pollTx = 0;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FATAL_ERROR;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return SSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_accept(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            if (err == SSL_ERROR_WANT_READ) {
                pollRx = 1;
            }
            else if (err == SSL_ERROR_WANT_WRITE) {
                pollTx = 1;
            }

        #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
            ret = socketSelect(sockfd, (int)timeout, pollRx);
        #else
            ret = socketPoll(sockfd, (int)timeout, pollRx, pollTx);
        #endif
            if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                /* loop around and try wolfSSL_accept() again */
                continue;
            } else if (ret == WOLFJNI_IO_EVENT_TIMEOUT ||
                       ret == WOLFJNI_IO_EVENT_FD_CLOSED ||
                       ret == WOLFJNI_IO_EVENT_ERROR ||
                       ret == WOLFJNI_IO_EVENT_POLLHUP ||
                       ret == WOLFJNI_IO_EVENT_FAIL) {
                /* Java will throw SocketTimeoutException or
                 * SocketException */
                break;
            } else {
                /* other error occurred */
                ret = SSL_FAILURE;
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeSSL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jobject* g_cachedSSLObj;
    jobject* g_cachedVerifyCb;
    jclass excClass;
    SSLAppData* appData;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;
#if defined(HAVE_PK_CALLBACKS) && (defined(HAVE_ECC) || !defined(NO_RSA))
    internCtx* pkCtx = NULL;
#endif

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");

    if (ssl == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in freeSSL");
        return;
    }

    /* free session mutex lock */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData != NULL) {
        if (appData->jniSessLock != NULL) {
            wc_FreeMutex(appData->jniSessLock);
            XFREE(appData->jniSessLock, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            appData->jniSessLock = NULL;
        }
        g_cachedVerifyCb = appData->g_verifySSLCbIfaceObj;
        if (g_cachedVerifyCb != NULL) {
            (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedVerifyCb));
            XFREE(g_cachedVerifyCb, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            g_cachedVerifyCb = NULL;
        }
        /* free appData */
        XFREE(appData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        appData = NULL;
    }

    /* delete global WolfSSLSession object reference */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (g_cachedSSLObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, (jobject)(*g_cachedSSLObj));
        XFREE(g_cachedSSLObj, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        g_cachedSSLObj = NULL;
    }

    /* reset internal pointer to NULL to prevent accidental usage */
    if (wolfSSL_set_jobject(ssl, NULL) != SSL_SUCCESS) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Error reseting internal wolfSSL JNI pointer to NULL, freeSSL");
        return;
    }

#ifdef HAVE_CRL
    /* release global CRL callback ref if registered */
    if (g_crlCbIfaceObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, g_crlCbIfaceObj);
        g_crlCbIfaceObj = NULL;
    }
#endif

#if defined(HAVE_PK_CALLBACKS)
    #ifdef HAVE_ECC
        /* free ECC sign callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetEccSignCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free ECC verify callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetEccVerifyCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free ECC shared secret callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetEccSharedSecretCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif /* HAVE_ECC */

    #ifndef NO_RSA
        /* free RSA sign callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaSignCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA verify callback CTX global reference if set */
        pkCtx = (internCtx*)wolfSSL_GetRsaVerifyCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA encrypt callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaEncCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }

        /* free RSA decrypt callback CTX global reference if set */
        pkCtx = (internCtx*) wolfSSL_GetRsaDecCtx(ssl);
        if (pkCtx != NULL) {
            if (pkCtx->obj != NULL) {
                (*jenv)->DeleteGlobalRef(jenv, pkCtx->obj);
            }
            XFREE(pkCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    #endif /* !NO_RSA */
#endif /* HAVE_PK_CALLBACKS */

    /* native cleanup */
    wolfSSL_free(ssl);
    ssl = 0;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_shutdownSSL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint timeout)
{
    int ret = 0, err, sockfd;
    int pollRx = 0;
    int pollTx = 0;
    wolfSSL_Mutex* jniSessLock;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* make sure we don't have any outstanding exceptions pending */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        return WOLFSSL_FAILURE;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        return WOLFSSL_FAILURE;
    }

    do {
        /* get I/O lock */
        if (wc_LockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        ret = wolfSSL_shutdown(ssl);
        err = wolfSSL_get_error(ssl, ret);

        /* release I/O lock */
        if (wc_UnLockMutex(jniSessLock) != 0) {
            ret = WOLFSSL_FAILURE;
            break;
        }

        if (ret < 0 && ((err == SSL_ERROR_WANT_READ) ||
                        (err == SSL_ERROR_WANT_WRITE))) {

            sockfd = wolfSSL_get_fd(ssl);
            if (sockfd == -1) {
                /* For I/O that does not use sockets, sockfd may be -1,
                 * skip try to call select() */
                break;
            }

            if (err == SSL_ERROR_WANT_READ) {
                pollRx = 1;
            }
            else if (err == SSL_ERROR_WANT_WRITE) {
                pollTx = 1;
            }

        #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
            ret = socketSelect(sockfd, (int)timeout, pollRx);
        #else
            ret = socketPoll(sockfd, (int)timeout, pollRx, pollTx);
        #endif
            if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                /* loop around and try wolfSSL_shutdown() again */
                continue;
            } else if (ret == WOLFJNI_IO_EVENT_TIMEOUT ||
                       ret == WOLFJNI_IO_EVENT_FD_CLOSED ||
                       ret == WOLFJNI_IO_EVENT_ERROR ||
                       ret == WOLFJNI_IO_EVENT_POLLHUP ||
                       ret == WOLFJNI_IO_EVENT_FAIL) {
                /* Java will throw SocketTimeoutException or
                 * SocketException */
                break;
            } else {
                /* other error occurred */
                ret = SSL_FAILURE;
                break;
            }
        }

    } while (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ);

    /* check for Java exceptions beofre returning */
    if ((*jenv)->ExceptionCheck(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getError
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint ret)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return SSL_FAILURE;
    }

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_get_error(ssl, ret);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSession
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong sessionPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    int ret = 0;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return SSL_FAILURE;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        printf("Failed to get SSLAppData* in native setSession()\n");
        return (jlong)0;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        printf("SSLAppData* NULL in native setSession()\n");
        return (jlong)0;
    }

    /* get WOLFSSL session I/O lock */
    if (wc_LockMutex(jniSessLock) != 0) {
        printf("Failed to lock native jniSessLock in setSession()");
        return (jlong)0;
    }

    /* wolfSSL checks session for NULL, but not ssl */
    ret = wolfSSL_set_session(ssl, session);

    if (wc_UnLockMutex(jniSessLock) != 0) {
        printf("Failed to unlock jniSessLock in setSession()");
    }

    return ret;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSession
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    WOLFSSL_SESSION* sess = NULL;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;
    (void)jenv;
    (void)jcl;

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        printf("Failed to get SSLAppData* in native getSession()\n");
        return (jlong)0;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        printf("SSLAppData* NULL in native getSession()\n");
        return (jlong)0;
    }

    /* get WOLFSSL session I/O lock */
    if (wc_LockMutex(jniSessLock) != 0) {
        printf("Failed to lock native jniSessLock in getSession()");
        return (jlong)0;
    }

    /* wolfSSL checks ssl for NULL, returns pointer into WOLFSSL which is
     * freed when wolfSSL_free() is called. */
    sess = wolfSSL_get_session(ssl);

    if (wc_UnLockMutex(jniSessLock) != 0) {
        printf("Failed to unlock jniSessLock in getSession()");
    }

    return (jlong)(uintptr_t)sess;
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_get1Session
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret = 0;
    int err = 0;
    int sockfd = 0;
    int version = 0;
    int hasTicket = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    WOLFSSL_SESSION* sess = NULL;
    WOLFSSL_SESSION* dup = NULL;
    wolfSSL_Mutex* jniSessLock = NULL;
    SSLAppData* appData = NULL;

    /* tmpBuf is only 1 byte since wolfSSL_peek() doesn't need to read
     * any app data, only session ticket internally */
    char tmpBuf[1];

    (void)jenv;
    (void)jcl;

    if (ssl == NULL) {
        return (jlong)0;
    }

    /* get session mutex from SSL app data */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData == NULL) {
        printf("Failed to get SSLAppData* in native get1Session()\n");
        return (jlong)0;
    }

    jniSessLock = appData->jniSessLock;
    if (jniSessLock == NULL) {
        printf("SSLAppData* NULL in native get1Session()\n");
        return (jlong)0;
    }

    /* get WOLFSSL session I/O lock */
    if (wc_LockMutex(jniSessLock) != 0) {
        printf("Failed to lock native jniSessLock in get1Session()");
        return (jlong)0;
    }

    /* get protocol version for this session */
    version = wolfSSL_version(ssl);

    /* Use wolfSSL_get_session() only as an indicator if we need to call
     * wolfSSL_peek() for TLS 1.3 connections to potentially get the
     * session ticket message. */
    sess = wolfSSL_get_session(ssl);

    /* Check if session has session ticket, checks sess for null internal */
    hasTicket = wolfSSL_SESSION_has_ticket((const WOLFSSL_SESSION*)sess);

    /* If session is not available yet, or if TLS 1.3 and we have a session
     * pointer but no session ticket yet, try peeking to get ticket */
    if (sess == NULL ||
        ((sess != NULL) && (version == TLS1_3_VERSION) && (hasTicket == 0))) {

        do {
            ret = wolfSSL_peek(ssl, tmpBuf, (int)sizeof(tmpBuf));
            err = wolfSSL_get_error(ssl, ret);

            if (ret <= 0 && (err == SSL_ERROR_WANT_READ)) {

                sockfd = wolfSSL_get_fd(ssl);
                if (sockfd == -1) {
                    /* For I/O that does not use sockets, sockfd may be -1,
                     * skip try to call select() */
                    break;
                }

            #if defined(WOLFJNI_USE_IO_SELECT) || defined(USE_WINDOWS_API)
                /* Default to select() on Windows or if WOLFJNI_USE_IO_SELECT */
                ret = socketSelect(sockfd,
                        (int)WOLFSSL_JNI_DEFAULT_PEEK_TIMEOUT, 1);
            #else
                ret = socketPoll(sockfd,
                        (int)WOLFSSL_JNI_DEFAULT_PEEK_TIMEOUT, 1, 0);
            #endif
                if ((ret == WOLFJNI_IO_EVENT_RECV_READY) ||
                    (ret == WOLFJNI_IO_EVENT_SEND_READY)) {
                    /* I/O ready, continue handshake and try again */
                    continue;
                } else {
                    /* other error, continue on */
                    break;
                }
            }
        } while (err == SSL_ERROR_WANT_READ);

        sess = wolfSSL_get_session(ssl);
        hasTicket = wolfSSL_SESSION_has_ticket((const WOLFSSL_SESSION*)sess);
    }

    /* Only duplicate / save session if not TLS 1.3 (will be using normal
     * session IDs), or is TLS 1.3 and we have a session ticket */
    if (version != TLS1_3_VERSION || hasTicket == 1) {

        /* wolfSSL checks ssl for NULL, returns pointer to new WOLFSSL_SESSION,
         * Returns new duplicated WOLFSSL_SESSION. Needs to be freed with
         * wolfSSL_SESSION_free() when finished with pointer. */
        if (sess != NULL) {
            /* Guarantee that we own the WOLFSSL_SESSION, make a copy */
            dup = wolfSSL_SESSION_dup(sess);
        }
    }

    if (wc_UnLockMutex(jniSessLock) != 0) {
        printf("Failed to unlock jniSessLock in get1Session()");
    }

    return (jlong)(uintptr_t)dup;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionIsSetup
  (JNIEnv* jenv, jclass jcl, jlong sessionPtr)
{
#if (LIBWOLFSSL_VERSION_HEX > 0x05007000) || \
    defined(WOLFSSL_PR7430_PATCH_APPLIED)
    int ret;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    /* wolfSSL_SessionIsSetup() was added after wolfSSL 5.7.0 in PR
     * 7430. Version checked above must be greater than 5.7.0 or patch
     * from this PR must be applied and WOLFSSL_PR7430_PATCH_APPLIED defined
     * when compiling this JNI wrapper */
    ret = wolfSSL_SessionIsSetup(session);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sessionPtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionIsResumable
  (JNIEnv* jenv, jclass jcl, jlong sessionPtr)
{
#ifdef OPENSSL_EXTRA
    int ret;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    ret = wolfSSL_SESSION_is_resumable(session);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sessionPtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionDup
  (JNIEnv* jenv, jclass jcl, jlong sessionPtr)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    /* checks session for NULL */
    return (jlong)(uintptr_t)wolfSSL_SESSION_dup(session);
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_wolfsslSessionCipherGetName
  (JNIEnv* jenv, jclass jcl, jlong sessionPtr)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    const char* cipherName;
    jstring cipherStr = NULL;
    (void)jcl;

    if (jenv == NULL || session == NULL) {
        return NULL;
    }

    cipherName = wolfSSL_SESSION_CIPHER_get_name(session);

    if (cipherName != NULL) {
        cipherStr = (*jenv)->NewStringUTF(jenv, cipherName);
    }

    return cipherStr;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_freeNativeSession
  (JNIEnv* jenv, jclass jcl, jlong sessionPtr)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL) {
        return;
    }

    /* checks session for NULL */
    wolfSSL_SESSION_free(session);
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSessionID
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr)
{
    unsigned int sz;
    const unsigned char* id;
    jbyteArray ret;
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;

    id = wolfSSL_SESSION_get_id(session, &sz);
    if (id == NULL) {
        return NULL;
    }

    ret = (*jenv)->NewByteArray(jenv, sz);
    if (!ret) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native getSessionID");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, ret, 0, sz, (jbyte*)id);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong t)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_set_timeout(ssl, (unsigned int)t);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_get_timeout(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setServerID
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray id, jint len, jint newSess)
{
#if !defined(NO_SESSION_CACHE) && !defined(NO_CLIENT_CACHE)
    int ret = WOLFSSL_SUCCESS;
    byte* idBuf = NULL;
    int idBufSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || id == NULL) {
        return WOLFSSL_FAILURE;
    }

    idBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, id, NULL);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }
    idBufSz = (*jenv)->GetArrayLength(jenv, id);

    if (idBuf == NULL || idBufSz <= 0) {
        ret = WOLFSSL_FAILURE;
    }
    else {
        ret = wolfSSL_SetServerID(ssl, idBuf, idBufSz, (int)newSess);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, id, (jbyte*)idBuf, JNI_ABORT);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)id;
    (void)len;
    (void)newSess;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr, jlong sz)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_SSL_SESSION_set_timeout(session, (long)sz);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getSessTimeout
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr)
{
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jenv;
    (void)jcl;

    return wolfSSL_SESSION_get_timeout(session);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCipherList
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring list)
{

    jint ret = 0;
    const char* cipherList;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || list == NULL) {
        return SSL_FAILURE;
    }

    cipherList= (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = (jint) wolfSSL_set_cipher_list(ssl, cipherList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, cipherList);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetCurrentTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "dtlsGetCurrentTimeout()");
        return 0;
    }

    return wolfSSL_dtls_get_current_timeout(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGotTimeout
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if !defined(WOLFSSL_LEANPSK) && defined(WOLFSSL_DTLS)
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FATAL_ERROR;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "dtlsGotTimeout()");
        return SSL_FATAL_ERROR;
    }

    return wolfSSL_dtls_got_timeout(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtls
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return 0;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in dtls()");
        return 0;
    }

    return wolfSSL_dtls(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_dtlsSetPeer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jobject peer)
{
    int ret = SSL_SUCCESS;
    jstring ipAddr = NULL;
    struct sockaddr_in sa;
    const char* ipAddress = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    jclass excClass = NULL;
    jclass inetsockaddr = NULL;
    jclass inetaddr = NULL;
    jmethodID portID = NULL;
    jmethodID addrID = NULL;
    jmethodID isAnyID = NULL;
    jmethodID ipAddrID = NULL;
    jobject addrObj = NULL;
    jboolean isAny;
    jint port = 0;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || peer == NULL) {
        return SSL_FAILURE;
    }

    /* get class references */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    inetsockaddr = (*jenv)->FindClass(jenv, "java/net/InetSocketAddress");
    inetaddr = (*jenv)->FindClass(jenv, "java/net/InetAddress");

    /* get port */
    portID = (*jenv)->GetMethodID(jenv, inetsockaddr, "getPort", "()I");
    if (!portID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't get getPort() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    port = (*jenv)->CallIntMethod(jenv, peer, portID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* get InetAddress object */
    addrID = (*jenv)->GetMethodID(jenv, inetsockaddr, "getAddress",
            "()Ljava/net/InetAddress;");
    if (!addrID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't get getAddress() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    addrObj = (*jenv)->CallObjectMethod(jenv, peer, addrID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* is this a wildcard address, ie: INADDR_ANY? */
    isAnyID = (*jenv)->GetMethodID(jenv, inetaddr, "isAnyLocalAddress", "()Z");
    if (!isAnyID) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get isAnyLocalAddress() method ID");
        return SSL_FAILURE;
    }
    (*jenv)->ExceptionClear(jenv);
    isAny = (*jenv)->CallBooleanMethod(jenv, addrObj, isAnyID);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        /* an exception occurred on the Java side, how to handle it? */
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    /* get IP address as a String */
    if (!isAny) {
        ipAddrID = (*jenv)->GetMethodID(jenv, inetaddr,
                "getHostAddress", "()Ljava/lang/String;");
        if (!ipAddrID) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't get getHostAddress() method ID");
            return SSL_FAILURE;
        }
        ipAddr = (*jenv)->CallObjectMethod(jenv, addrObj, ipAddrID);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* an exception occurred on the Java side, how to handle it? */
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        /* convert IP string to char* */
        ipAddress = (*jenv)->GetStringUTFChars(jenv, ipAddr, 0);
    }

    /* build sockaddr_in */
    memset(&sa, 0, sizeof(struct sockaddr_in));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((int)port);
    if (isAny) {
        sa.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (XINET_PTON(AF_INET, ipAddress, &sa.sin_addr.s_addr) < 1) {
            ret = SSL_FAILURE;
        }
    }

    if (ret == SSL_SUCCESS) {
        /* call native wolfSSL function */
        ret = wolfSSL_dtls_set_peer(ssl, &sa, sizeof(sa));
    }

    if (!isAny) {
        (*jenv)->ReleaseStringUTFChars(jenv, ipAddr, ipAddress);
    }

    return ret;
}

/* max IP size IPv4 mapped IPv6 */
#define MAX_EXPORT_IP 46

JNIEXPORT jobject JNICALL Java_com_wolfssl_WolfSSLSession_dtlsGetPeer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret, port;
    unsigned int peerSz;
    struct sockaddr_in peer;
#ifdef USE_WINDOWS_API
    int ipAddrStringSz = MAX_EXPORT_IP;
    WCHAR ipAddrWStr[MAX_EXPORT_IP];
    char ipAddrString[MAX_EXPORT_IP];
#else
    char ipAddrString[MAX_EXPORT_IP];
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;

    jmethodID constr;
    jstring ipAddr;
    jclass excClass = NULL;
    jclass isa = NULL;

    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    /* get native sockaddr_in peer */
    memset(&peer, 0, sizeof(peer));
    peerSz = sizeof(peer);
    ret = wolfSSL_dtls_get_peer(ssl, &peer, &peerSz);
    if (ret != SSL_SUCCESS) {
        return NULL;
    }

    XMEMSET(ipAddrString, 0, sizeof(ipAddrString));
#ifdef USE_WINDOWS_API
    if (XINET_NTOP((int)peer.sin_family, &(peer.sin_addr),
                   ipAddrWStr, INET_ADDRSTRLEN) == NULL) {
        return NULL;
    }
    /* Convert WCHAR to char* */
    if (WideCharToMultiByte(CP_ACP, 0, ipAddrWStr, -1, ipAddrString,
                            MAX_EXPORT_IP, NULL, NULL) == 0) {
        return NULL;
    }
#else
    if (XINET_NTOP(AF_INET, &(peer.sin_addr),
        ipAddrString, INET_ADDRSTRLEN) == NULL) {
        return NULL;
    }
#endif
    port = ntohs(peer.sin_port);

    /* create new InetSocketAddress with this IP/port info */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    isa = (*jenv)->FindClass(jenv, "java/net/InetSocketAddress");
    if (!isa) {
        if ((*jenv)->ExceptionOccurred(jenv))
            (*jenv)->ExceptionClear(jenv);

        (*jenv)->ThrowNew(jenv, excClass, "Can't find InetSocketAddress class");
        return NULL;
    }

    /* create jstring from char* */
    ipAddr = (*jenv)->NewStringUTF(jenv, ipAddrString);

    /* find correct InetSocketAddress constructor */
    if (peer.sin_addr.s_addr != INADDR_ANY) {

        constr = (*jenv)->GetMethodID(jenv, isa, "<init>",
                "(Ljava/lang/String;I)V");
        if (!constr) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't find InetSocketAddress(String,port)");
            return NULL;
        }

        return (*jenv)->NewObject(jenv, isa, constr, ipAddr, port);

    } else { /* sockaddr_in was created with INADDR_ANY, use wildcard IP */

        constr = (*jenv)->GetMethodID(jenv, isa, "<init>",
                "(I)V");
        if (!constr) {
            if ((*jenv)->ExceptionOccurred(jenv))
                (*jenv)->ExceptionClear(jenv);

            (*jenv)->ThrowNew(jenv, excClass,
                    "Can't find InetSocketAddress(port)");
            return NULL;
        }

        return (*jenv)->NewObject(jenv, isa, constr, port);
    }
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sessionReused
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in sessionReused()");
        return SSL_FAILURE;
    }

    return wolfSSL_session_reused(ssl);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getPeerCertificate
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef KEEP_PEER_CERT
    WOLFSSL_X509* x509 = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    if (ssl == NULL) {
        return (jlong)0;
    }

    x509 = wolfSSL_get_peer_certificate(ssl);

    return (jlong)(uintptr_t)x509;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return (jlong)0;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Issuer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* issuer;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)sslPtr;
    (void)jcl;

    if (x509 == NULL) {
        return NULL;
    }

    issuer = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_issuer_name(x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, issuer);
    XFREE(issuer, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509Subject
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{

#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* subject;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)sslPtr;
    (void)jcl;

    if (x509 == NULL) {
        return NULL;
    }

    subject = wolfSSL_X509_NAME_oneline(
            wolfSSL_X509_get_subject_name(x509), 0, 0);

    retString = (*jenv)->NewStringUTF(jenv, subject);
    XFREE(subject, 0, DYNAMIC_TYPE_OPENSSL);

    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPeerX509AltName
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong x509Ptr)
{
#if defined(KEEP_PEER_CERT) || defined(SESSION_CERTS)
    char* altname;
    jstring retString;
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509Ptr;
    (void)jcl;
    (void)sslPtr;

    if (x509 == NULL) {
        return NULL;
    }

    altname = wolfSSL_X509_get_next_altname(x509);

    retString = (*jenv)->NewStringUTF(jenv, altname);
    return retString;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)x509Ptr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getVersion
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getVersion");
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_version(ssl));
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getCurrentCipher
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "getVersion");
        return SSL_FAILURE;
    }

    return (jlong)(uintptr_t)wolfSSL_get_current_cipher(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_checkDomainName
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring dn)
{
    int ret;
    const char* dname;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if(dn == NULL) {
        return SSL_FAILURE;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "checkDomainName");
        return SSL_FAILURE;
    }

    dname = (*jenv)->GetStringUTFChars(jenv, dn, 0);

    ret = wolfSSL_check_domain_name(ssl, dname);

    (*jenv)->ReleaseStringUTFChars(jenv, dn, dname);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDH
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray p, jint pSz,
   jbyteArray g, jint gSz)
{
#ifndef NO_DH
    int ret;
    jclass excClass;
    unsigned char* pBuf = NULL;
    unsigned char* gBuf = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || p == NULL || g == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setTmpDH");
        return SSL_FAILURE;
    }

    pBuf = (unsigned char*)XMALLOC((int)pSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pBuf == NULL) {
        return MEMORY_E;
    }
    XMEMSET(pBuf, 0, pSz);

    gBuf = (unsigned char*)XMALLOC((int)gSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (gBuf == NULL) {
        XFREE(pBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
    XMEMSET(gBuf, 0, gSz);

    (*jenv)->GetByteArrayRegion(jenv, p, 0, pSz, (jbyte*)pBuf);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(pBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(gBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return SSL_FAILURE;
    }

    (*jenv)->GetByteArrayRegion(jenv, g, 0, gSz, (jbyte*)gBuf);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(pBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(gBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return SSL_FAILURE;
    }

    ret = wolfSSL_SetTmpDH(ssl, pBuf, pSz, gBuf, gSz);

    XFREE(pBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(gBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)p;
    (void)pSz;
    (void)g;
    (void)gSz;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTmpDHFile
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring file, jint format)
{
#if !defined(NO_DH) && !defined(NO_FILESYSTEM)
    int ret;
    const char* fname;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (file == NULL) {
        return SSL_BAD_FILE;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setTmpDHFile");
        return SSL_FAILURE;
    }

    fname = (*jenv)->GetStringUTFChars(jenv, file, 0);

    ret = wolfSSL_SetTmpDH_file(ssl, fname, format);

    (*jenv)->ReleaseStringUTFChars(jenv, file, fname);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)file;
    (void)format;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz,
   jint format)
{
    int ret = SSL_SUCCESS;
    jclass excClass;
    unsigned char* buff = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "useCertificateBuffer");
        return SSL_FAILURE;
    }

    buff = (unsigned char*)XMALLOC((int)sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        return MEMORY_E;
    }
    XMEMSET(buff, 0, (int)sz);

    (*jenv)->GetByteArrayRegion(jenv, in, 0, (long)sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return SSL_FAILURE;
    }

    ret = wolfSSL_use_certificate_buffer(ssl, buff, (long)sz, format);

    XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePrivateKeyBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz,
   jint format)
{
    int ret;
    jclass excClass;
    unsigned char* buff = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "usePrivateKeyBuffer");
        return SSL_FAILURE;
    }

    buff = (unsigned char*)XMALLOC((long)sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        return MEMORY_E;
    }
    XMEMSET(buff, 0, (long)sz);

    (*jenv)->GetByteArrayRegion(jenv, in, 0, (long)sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return SSL_FAILURE;
    }

    ret = wolfSSL_use_PrivateKey_buffer(ssl, buff, (long)sz, format);

    XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBuffer
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz)
{
    int ret;
    jclass excClass;
    unsigned char* buff = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || in == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "useCertificateChainBuffer");
        return SSL_FAILURE;
    }

    buff = (unsigned char*)XMALLOC((long)sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buff == NULL) {
        return MEMORY_E;
    }
    XMEMSET(buff, 0, (long)sz);

    (*jenv)->GetByteArrayRegion(jenv, in, 0, (long)sz, (jbyte*)buff);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return SSL_FAILURE;
    }

    ret = wolfSSL_use_certificate_chain_buffer(ssl, buff, (long)sz);

    XFREE(buff, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useCertificateChainBufferFormat
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray in, jlong sz, jint format)
{
    int ret = WOLFSSL_FAILURE;
    byte* buff = NULL;
    word32 buffSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;
    (void)sz;

    if (jenv == NULL || ssl == NULL || in == NULL) {
        return (jint)BAD_FUNC_ARG;
    }

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, in, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, in);

    if (buff != NULL && buffSz > 0) {
        ret = wolfSSL_use_certificate_chain_buffer_format(
                ssl, buff, buffSz, format);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, in, (jbyte*)buff, JNI_ABORT);

    return (jint)ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setGroupMessages
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "setGroupMessages");
        return BAD_FUNC_ARG;
    }
    return wolfSSL_set_group_messages(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_enableCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint options)
{
#ifdef HAVE_CRL
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "enableCRL");
        return SSL_FAILURE;
    }

    return wolfSSL_EnableCRL(ssl, options);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)options;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_disableCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef HAVE_CRL
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "disableCRL");
        return SSL_FAILURE;
    }

    return wolfSSL_DisableCRL(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_loadCRL
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring path, jint type,
   jint monitor)
{
#if defined(HAVE_CRL) && !defined(NO_FILESYSTEM)
    int ret;
    const char* crlPath;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || path == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return SSL_FAILURE;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "loadCRL");
        return SSL_FAILURE;
    }

    crlPath = (*jenv)->GetStringUTFChars(jenv, path, 0);

    ret = wolfSSL_LoadCRL(ssl, crlPath, type, monitor);

    (*jenv)->ReleaseStringUTFChars(jenv, path, crlPath);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)path;
    (void)type;
    (void)monitor;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setCRLCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jobject cb)
{
#ifdef HAVE_CRL
    int    ret = 0;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL) {
        return BAD_FUNC_ARG;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return SSL_FAILURE;
    }

    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was NULL in "
            "setCRLCb");
        return SSL_FAILURE;
    }

    /* release global CRL callback ref if already registered */
    if (g_crlCbIfaceObj != NULL) {
        (*jenv)->DeleteGlobalRef(jenv, g_crlCbIfaceObj);
        g_crlCbIfaceObj = NULL;
    }

    if (cb != NULL) {
        /* store Java CRL callback Interface object */
        g_crlCbIfaceObj = (*jenv)->NewGlobalRef(jenv, cb);
        if (g_crlCbIfaceObj == NULL) {
            (*jenv)->ThrowNew(jenv, excClass,
                   "Error storing global missingCRLCallback interface");
        }

        ret = wolfSSL_SetCRL_Cb(ssl, NativeMissingCRLCallback);
    }

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)cb;
    return NOT_COMPILED_IN;
#endif
}

#ifdef HAVE_CRL

void NativeMissingCRLCallback(const char* url)
{
    JNIEnv*   jenv;
    jint      vmret  = 0;
    jclass    excClass = NULL;
    jclass    crlClass = NULL;
    jmethodID crlMethod = NULL;
    jobjectRefType refcheck;
    jstring missingUrl = NULL;

    /* get JNIEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            printf("Failed to attach JNIEnv to thread\n");
        }
    } else if (vmret != JNI_OK) {
        printf("Unable to get JNIEnv from JavaVM\n");
    }

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    /* check if our stored object reference is valid */
    refcheck = (*jenv)->GetObjectRefType(jenv, g_crlCbIfaceObj);
    if (refcheck == 2) {

        /* lookup WolfSSLMissingCRLCallback class from global object ref */
        crlClass = (*jenv)->GetObjectClass(jenv, g_crlCbIfaceObj);
        if (!crlClass) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLMissingCRLCallback class reference");
            return;
        }

        crlMethod = (*jenv)->GetMethodID(jenv, crlClass,
                                            "missingCRLCallback",
                                            "(Ljava/lang/String;)V");
        if (crlMethod == 0) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }

            (*jenv)->ThrowNew(jenv, excClass,
                "Error getting missingCRLCallback method from JNI");
            return;
        }

        /* create jstring from char* */
        missingUrl = (*jenv)->NewStringUTF(jenv, url);

        (*jenv)->CallVoidMethod(jenv, g_crlCbIfaceObj, crlMethod, missingUrl);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return;
        }

    } else {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }

        (*jenv)->ThrowNew(jenv, excClass,
                "Object reference invalid in NativeMissingCRLCallback");
    }
}

#endif /* HAVE_CRL */

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_cipherGetName
  (JNIEnv* jenv, jclass jcl, jlong sslPtr)
{
    const char* cipherName;
    WOLFSSL_CIPHER* cipher;
    jclass excClass;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (ssl == NULL) {
        excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null in "
                "cipherGetName");
        return NULL;
    }

    cipher = wolfSSL_get_current_cipher(ssl);

    if (cipher != NULL) {
        cipherName = wolfSSL_CIPHER_get_name(cipher);
        return (*jenv)->NewStringUTF(jenv, cipherName);
    } else {
        return (*jenv)->NewStringUTF(jenv, "NONE");
    }
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getMacSecret
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint verify)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int macLength;
    jbyteArray retSecret;
    const unsigned char* secret;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getMacSecret");
        return NULL;
    }

    secret = wolfSSL_GetMacSecret(ssl, (int)verify);

    if (secret != NULL) {

        /* get mac size */
        macLength = wolfSSL_GetHmacSize(ssl);

        /* create byte array to return */
        retSecret = (*jenv)->NewByteArray(jenv, macLength);
        if (!retSecret) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getMacSecret");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retSecret, 0, macLength,
                (jbyte*)secret);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retSecret;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteKey
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    int keyLength;
    jbyteArray retKey;
    const unsigned char* key;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteKey");
        return NULL;
    }

    key = wolfSSL_GetClientWriteKey(ssl);
    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize(ssl);

        /* create byte array to return */
        retKey = (*jenv)->NewByteArray(jenv, keyLength);
        if (!retKey) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getClientWriteKey");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retKey, 0, keyLength,
                (jbyte*)key);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retKey;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientWriteIV
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getClientWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetClientWriteIV(ssl);
    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize(ssl);

        /* create byte array to return */
        retIV = (*jenv)->NewByteArray(jenv, ivLength);
        if (!retIV) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getClientWriteIV");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retIV, 0, ivLength,
                (jbyte*)iv);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retIV;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteKey
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retKey;
    const unsigned char* key;
    int keyLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteKey");
        return NULL;
    }

    key = wolfSSL_GetServerWriteKey(ssl);
    if (key != NULL) {

        /* get key size */
        keyLength = wolfSSL_GetKeySize(ssl);

        /* create byte array to return */
        retKey = (*jenv)->NewByteArray(jenv, keyLength);
        if (!retKey) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getServerWriteKey");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retKey, 0, keyLength,
                (jbyte*)key);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retKey;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getServerWriteIV
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass excClass;
#ifdef ATOMIC_USER
    jbyteArray retIV;
    const unsigned char* iv;
    int ivLength;
#endif
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef ATOMIC_USER
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "getServerWriteIV");
        return NULL;
    }

    iv = wolfSSL_GetServerWriteIV(ssl);
    if (iv != NULL) {

        /* get iv size, is block size for what wolfSSL supports */
        ivLength = wolfSSL_GetCipherBlockSize(ssl);

        /* create byte array to return */
        retIV = (*jenv)->NewByteArray(jenv, ivLength);
        if (!retIV) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create byte array in native getServerWriteIV");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, retIV, 0, ivLength,
                (jbyte*)iv);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return retIV;

    } else {
        return NULL;
    }
#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with ATOMIC_USER");
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getKeySize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetKeySize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getSide
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetSide((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_isTLSv1_11
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_IsTLSv1_1((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getBulkCipher
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetBulkCipher((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherBlockSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherBlockSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getAeadMacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetAeadMacSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacSize
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacSize((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getHmacType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetHmacType((WOLFSSL*)(uintptr_t)ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getCipherType
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;

#ifdef ATOMIC_USER
    /* wolfSSL checks ssl for NULL */
    return wolfSSL_GetCipherType((WOLFSSL*)(uintptr_t)ssl);
#else
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTlsHmacInner
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray inner, jlong sz,
   jint content, jint verify)
{
    int ret = 0;
    unsigned char hmacInner[WOLFSSL_TLS_HMAC_INNER_SZ];
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || inner == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return -1;
    }

    ret = wolfSSL_SetTlsHmacInner(ssl, hmacInner, (long)sz, content, verify);

    /* copy hmacInner back into inner jbyteArray */
    (*jenv)->SetByteArrayRegion(jenv, inner, 0, WOLFSSL_TLS_HMAC_INNER_SZ,
            (jbyte*)hmacInner);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to set byte region in native setTlsHmacInner");
        return -1;
    }

    return ret;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSignCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSignCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccSignCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccSignCtx = (internCtx*) wolfSSL_GetEccSignCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSignCtx != NULL) {
        myCtx = (internCtx*)eccSignCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC sign context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (!myCtx->obj) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccSignCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccVerifyCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccVerifyCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccVerifyCtx = (internCtx*)wolfSSL_GetEccVerifyCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccVerifyCtx != NULL) {
        myCtx = (internCtx*)eccVerifyCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (!myCtx) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC verify context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccVerifyCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setEccSharedSecretCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    jclass         sslClass;

    void*          eccSharedSecretCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && defined(HAVE_ECC)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setEccSharedSecretCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    eccSharedSecretCtx = (internCtx*) wolfSSL_GetEccSharedSecretCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (eccSharedSecretCtx != NULL) {
        myCtx = (internCtx*)eccSharedSecretCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for ECC shared secret context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetEccSharedSecretCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or ECC");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaSignCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaSignCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaSignCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaSignCtx = (internCtx*) wolfSSL_GetRsaSignCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaSignCtx != NULL) {
        myCtx = (internCtx*)rsaSignCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA sign context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaSignCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaVerifyCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaVerifyCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaVerifyCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaVerifyCtx = (internCtx*)wolfSSL_GetRsaVerifyCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaVerifyCtx != NULL) {
        myCtx = (internCtx*)rsaVerifyCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA verify context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaVerifyCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaEncCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaEncCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)

    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaEncCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaEncCtx = (internCtx*) wolfSSL_GetRsaEncCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaEncCtx != NULL) {
        myCtx = (internCtx*)rsaEncCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA encrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaEncCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setRsaDecCtx
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    jclass         excClass;
#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    jclass         sslClass;

    void*          rsaDecCtx;
    internCtx*     myCtx;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#endif

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#if defined(HAVE_PK_CALLBACKS) && !defined(NO_RSA)
    if (ssl == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Input WolfSSLSession object was null in "
            "setRsaDecCtx");
        return;
    }

    /* get WolfSSLSession class from object ref */
    sslClass = (*jenv)->GetObjectClass(jenv, jcl);
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get WolfSSLSession object class");
        return;
    }

    /* free existing memory if it already exists, before we malloc again */
    rsaDecCtx = (internCtx*) wolfSSL_GetRsaDecCtx(ssl);

    /* note: if CTX has not been set up yet, wolfSSL defaults to NULL */
    if (rsaDecCtx != NULL) {
        myCtx = (internCtx*)rsaDecCtx;
        if (myCtx != NULL) {
            if (myCtx->active == 1) {
                (*jenv)->DeleteGlobalRef(jenv, myCtx->obj);
            }
            XFREE(myCtx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* allocate memory for internal JNI object reference */
    myCtx = XMALLOC(sizeof(internCtx), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (myCtx == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Unable to allocate memory for RSA decrypt context\n");
        return;
    }

    /* set CTX as active */
    myCtx->active = 1;

    /* store global ref to WolfSSLSession object */
    myCtx->obj = (*jenv)->NewGlobalRef(jenv, jcl);
    if (myCtx->obj == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
               "Unable to store WolfSSLSession object as global reference");
        return;
    }

    wolfSSL_SetRsaDecCtx(ssl, myCtx);
#else
    (void)jcl;
    (void)sslPtr;
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PK Callbacks and/or RSA support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskClientCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#ifndef NO_PSK
    if (ssl != NULL) {
        /* set PSK client callback */
        wolfSSL_set_psk_client_callback(ssl, NativePskClientCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskClientCb");
        return;
    }

#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PSK support");
    return;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setPskServerCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

#ifndef NO_PSK
    if (ssl != NULL) {
        /* set PSK server callback */
        wolfSSL_set_psk_server_callback(ssl, NativePskServerCb);
    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLSession object was null when setting "
                "NativePskServerCb");
        return;
    }

#else
    (*jenv)->ThrowNew(jenv, excClass,
        "wolfSSL not compiled with PSK support");
    return;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong sslPtr)
{
#ifndef NO_PSK
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_psk_identity_hint(ssl));
#else
    (void)jenv;
    (void)obj;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jstring JNICALL Java_com_wolfssl_WolfSSLSession_getPskIdentity
  (JNIEnv* jenv, jobject obj, jlong sslPtr)
{
#ifndef NO_PSK
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    return (*jenv)->NewStringUTF(jenv, wolfSSL_get_psk_identity(ssl));
#else
    (void)jenv;
    (void)obj;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_usePskIdentityHint
  (JNIEnv* jenv, jobject obj, jlong sslPtr, jstring hint)
{
#ifndef NO_PSK
    jint ret;
    const char* nativeHint;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)obj;

    if (jenv == NULL || ssl == NULL || hint == NULL) {
        return SSL_FAILURE;
    }

    nativeHint = (*jenv)->GetStringUTFChars(jenv, hint, 0);

    ret = (jint)wolfSSL_use_psk_identity_hint(ssl, nativeHint);

    (*jenv)->ReleaseStringUTFChars(jenv, hint, nativeHint);

    return ret;
#else
    (void)jenv;
    (void)sslPtr;
    (void)hint;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jboolean JNICALL Java_com_wolfssl_WolfSSLSession_handshakeDone
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return JNI_FALSE;
    }

    if (wolfSSL_is_init_finished(ssl)) {
        return JNI_TRUE;
    }
    else {
        return JNI_FALSE;
    }
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setConnectState
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    wolfSSL_set_connect_state(ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setAcceptState
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    wolfSSL_set_accept_state(ssl);
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setVerify
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint mode, jobject callbackIface)
{
    jobject* verifyCb = NULL;
    SSLAppData* appData = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return;
    }

    /* Release global reference if already set, before setting again */
    appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
    if (appData != NULL) {
        verifyCb = appData->g_verifySSLCbIfaceObj;
        if (verifyCb != NULL) {
            (*jenv)->DeleteGlobalRef(jenv, (jobject)(*verifyCb));
            XFREE(verifyCb, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            verifyCb = NULL;
            appData->g_verifySSLCbIfaceObj = NULL;
        }
    }

    /* Set verify callback to NULL (reset), or passed in callback */
    if (!callbackIface) {
        wolfSSL_set_verify(ssl, mode, NULL);
    }
    else {
        /* Get app data to store verify callback jobject */
        appData = (SSLAppData*)wolfSSL_get_app_data(ssl);
        if (appData == NULL) {
            printf("Error getting app data from WOLFSSL\n");
        }

        if (appData != NULL) {
            verifyCb = (jobject*)XMALLOC(sizeof(jobject), NULL,
                                         DYNAMIC_TYPE_TMP_BUFFER);
            if (verifyCb == NULL) {
                printf("Error allocating memory for verifyCb\n");
            }
        }

        if ((appData != NULL) && (verifyCb != NULL)) {
            /* store Java verify Interface object */
            *verifyCb = (*jenv)->NewGlobalRef(jenv, callbackIface);
            if (*verifyCb == NULL) {
                printf("error storing global callback interface\n");
		        XFREE(verifyCb, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
            else {
                appData->g_verifySSLCbIfaceObj = verifyCb;

                /* set verify mode, register Java callback with wolfSSL */
                wolfSSL_set_verify(ssl, mode, NativeSSLVerifyCallback);
            }
        }
    }
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_setOptions
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jlong op)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return 0;
    }

    return wolfSSL_set_options(ssl, (long)op);
}

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLSession_getOptions
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return 0;
    }

    return wolfSSL_get_options(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_getShutdown
  (JNIEnv *jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jenv;
    (void)jcl;

    return (jint)wolfSSL_get_shutdown(ssl);
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSNI
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyte type, jbyteArray data)
{
    int ret = SSL_FAILURE;
#ifdef HAVE_SNI
    byte* dataBuf = NULL;
    word32 dataSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    dataBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, data, NULL);
    dataSz = (*jenv)->GetArrayLength(jenv, data);

    if (dataBuf != NULL && dataSz > 0) {
        ret = wolfSSL_UseSNI(ssl, (byte)type, dataBuf, (word16)dataSz);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, data, (jbyte*)dataBuf, JNI_ABORT);

#else
    ret = NOT_COMPILED_IN;
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)type;
    (void)data;
#endif /* HAVE_SNI */

    return (jint)ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getSNIRequest
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyte type)
{
#ifdef HAVE_SNI
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    void* request = NULL;
    jbyteArray sniRequest;
    word16 ret = 0;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    ret = wolfSSL_SNI_GetRequest(ssl, (byte)type, &request);

    if (ret > 0) {
        sniRequest = (*jenv)->NewByteArray(jenv, ret);
        if (sniRequest == NULL) {
            (*jenv)->ThrowNew(jenv, jcl,
                "Failed to create byte array in native getSNIRequest");
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, sniRequest, 0, ret,
                                    (jbyte*)request);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            return NULL;
        }

        return sniRequest;
    }

    return NULL;

#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)type;
    return NULL;
#endif /* HAVE_SNI */
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSessionTicket
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret = SSL_FAILURE;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
#ifdef HAVE_SESSION_TICKET
    (void)jcl;
    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_UseSessionTicket(ssl);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

/* return 1 if last alert received was a close_notify alert, otherwise 0 */
JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_gotCloseNotify
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    int ret, gotCloseNotify = 0;
    WOLFSSL_ALERT_HISTORY alert_history;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return gotCloseNotify;
    }

    ret = wolfSSL_get_alert_history(ssl, &alert_history);
    if (ret == WOLFSSL_SUCCESS) {
        if (alert_history.last_rx.code == 0) {
            gotCloseNotify = 1;
        }
    }

    return gotCloseNotify;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_sslSetAlpnProtos
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jbyteArray alpnProtos)
{
    int ret = SSL_FAILURE;
#if defined(HAVE_ALPN) && (LIBWOLFSSL_VERSION_HEX >= 0x04002000)
    /* wolfSSL_set_alpn_protos() added as of wolfSSL 4.2.0 */
    byte* buff = NULL;
    word32 buffSz = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || alpnProtos == NULL) {
        return BAD_FUNC_ARG;
    }

    buff = (byte*)(*jenv)->GetByteArrayElements(jenv, alpnProtos, NULL);
    buffSz = (*jenv)->GetArrayLength(jenv, alpnProtos);

    if (buff != NULL && buffSz > 0) {
        ret = wolfSSL_set_alpn_protos(ssl, buff, buffSz);
#ifdef WOLFSSL_ERROR_CODE_OPENSSL
        if (ret == 0) {
            /* wolfSSL_set_alpn_protos() returns 0 on success if
             * WOLFSSL_ERROR_CODE_OPENSSL is defined, to match behavior of
             * OpenSSL for compatibility layer. We translate back to
             * a consistent SSL_SUCCESS here */
            ret = SSL_SUCCESS;
        }
        else {
            ret = SSL_FAILURE;
        }
#endif
    }

    (*jenv)->ReleaseByteArrayElements(jenv, alpnProtos,
                                      (jbyte*)buff, JNI_ABORT);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)alpnProtos;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_sslGet0AlpnSelected
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#ifdef HAVE_ALPN
    int err = 0;
    char* protocol_name = NULL;
    word16 protocol_nameSz = 0;
    jbyteArray alpnArray;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    /* get ALPN protocol received from server:
     * WOLFSSL_SUCCESS - on success
     * WOLFSSL_ALPN_NOT_FOUND - no ALPN received (no match with server)
     * other - error case */
    err = wolfSSL_ALPN_GetProtocol(ssl, &protocol_name, &protocol_nameSz);
    if (err != WOLFSSL_SUCCESS) {
        return NULL;
    }

    alpnArray = (*jenv)->NewByteArray(jenv, protocol_nameSz);
    if (alpnArray == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native sslGet0AlpnSelected");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, alpnArray, 0, protocol_nameSz,
                                (jbyte*)protocol_name);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return alpnArray;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useALPN
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring protocols, jint options)
{
    int ret = SSL_FAILURE;
#ifdef HAVE_ALPN
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    char* protoList = NULL;
    jsize protocolsLen = 0;
    (void)jcl;

    if (jenv == NULL || ssl == 0 || protocols == NULL || options < 0) {
        return BAD_FUNC_ARG;
    }

    protocolsLen = (*jenv)->GetStringUTFLength(jenv, protocols);
    if (protocolsLen == 0) {
        return BAD_FUNC_ARG;
    }

    /* Allocate size + 1 to guarantee we are null terminated */
    protoList = (char*)XMALLOC(protocolsLen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (protoList == NULL) {
        return MEMORY_E;
    }

    /* GetStringUTFRegion() does not need to be freed/released */
    (*jenv)->GetStringUTFRegion(jenv, protocols, 0, protocolsLen, protoList);
    protoList[protocolsLen] = '\0';

    ret = wolfSSL_UseALPN(ssl, protoList, protocolsLen, (int)options);

    XFREE(protoList, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)protocols;
    (void)options;
    ret = NOT_COMPILED_IN;
#endif

    return (jint)ret;
}

JNIEXPORT int JNICALL Java_com_wolfssl_WolfSSLSession_setALPNSelectCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if defined(HAVE_ALPN) && (LIBWOLFSSL_VERSION_HEX >= 0x05006006)
    /* wolfSSL_set_alpn_select_cb() added as of wolfSSL 5.6.6 */
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    int ret = SSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* set ALPN select callback */
    wolfSSL_set_alpn_select_cb(ssl, NativeALPNSelectCb, NULL);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

#ifdef HAVE_ALPN

int NativeALPNSelectCb(WOLFSSL *ssl, const unsigned char **out,
    unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    JNIEnv* jenv;                   /* JNI environment */
    jclass  excClass;               /* WolfSSLJNIException class */
    int     needsDetach = 0;        /* Should we explicitly detach? */
    jint    vmret = 0;

    jobject*  g_cachedSSLObj;       /* WolfSSLSession cached object */
    jclass    sslClass;             /* WolfSSLSession class */
    jmethodID alpnSelectMethodId;   /* internalAlpnSelectCallback ID */

    int ret = 0;
    unsigned int idx = 0;
    int peerProtoCount = 0;
    char* peerProtos = NULL;
    char* peerProtosCopy = NULL;
    word16 peerProtosSz = 0;
    char* curr = NULL;
    char* ptr = NULL;
    jobjectArray peerProtosArr = NULL;
    jobjectArray outProtoArr = NULL;
    int outProtoArrSz = 0;
    jstring selectedProto = NULL;
    const char* selectedProtoCharArr = NULL;
    int selectedProtoCharArrSz = 0;

    if (g_vm == NULL || ssl == NULL || out == NULL || outlen == NULL ||
        in == NULL) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }
        needsDetach = 1;
    }
    else if (vmret != JNI_OK) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* get stored WolfSSLSession object */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession object reference in "
            "NativeALPNSelectCb");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (sslClass == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference in "
            "NativeALPNSelectCb");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* call internal ALPN select callback */
    alpnSelectMethodId = (*jenv)->GetMethodID(jenv, sslClass,
        "internalAlpnSelectCallback",
        "(Lcom/wolfssl/WolfSSLSession;[Ljava/lang/String;[Ljava/lang/String;)I");
    if (alpnSelectMethodId == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalAlpnSelectCallback method from JNI");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* Use wolfSSL_ALPN_GetPeerProtocol() here to get ALPN protocols sent
     * by the peer instead of directly using in/inlen, since this API
     * splits/formats into a comma-separated, null-terminated list */
    ret = wolfSSL_ALPN_GetPeerProtocol(ssl, &peerProtos, &peerProtosSz);
    if (ret != WOLFSSL_SUCCESS) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error in wolfSSL_ALPN_GetPeerProtocol()");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* Make a copy of peer protos since we have to scan through it first
     * to get total number of tokens */
    peerProtosCopy = (char*)XMALLOC(peerProtosSz, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (peerProtosCopy == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error allocating memory for peer protocols array");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    XMEMCPY(peerProtosCopy, peerProtos, peerProtosSz);

    /* get count of protocols, used to create Java array of proper size */
    curr = XSTRTOK(peerProtosCopy, ",", &ptr);
    while (curr != NULL) {
        peerProtoCount++;
        curr = XSTRTOK(NULL, ",", &ptr);
    }
    XFREE(peerProtosCopy, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    peerProtosCopy = NULL;

    if (peerProtoCount == 0) {
        wolfSSL_ALPN_FreePeerProtocol(ssl, &peerProtos);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "ALPN peer protocol list size is 0");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* create Java String[] of size peerProtoCount */
    peerProtosArr = (*jenv)->NewObjectArray(jenv, peerProtoCount,
        (*jenv)->FindClass(jenv, "java/lang/String"), NULL);
    if (peerProtosArr == NULL) {
        wolfSSL_ALPN_FreePeerProtocol(ssl, &peerProtos);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to create JNI String[] for ALPN protocols");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* add each char* to String[] for call to Java callback method */
    curr = XSTRTOK(peerProtos, ",", &ptr);
    while (curr != NULL) {
        (*jenv)->SetObjectArrayElement(jenv, peerProtosArr, idx++,
            (*jenv)->NewStringUTF(jenv, curr));
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);

            wolfSSL_ALPN_FreePeerProtocol(ssl, &peerProtos);
            (*jenv)->ThrowNew(jenv, excClass,
                "Failed to add String to JNI String[] for ALPN protocols");
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        curr = XSTRTOK(NULL, ",", &ptr);
    }

    /* free native peer protocol list, no longer needed */
    wolfSSL_ALPN_FreePeerProtocol(ssl, &peerProtos);

    /* create new String[1] to let Java callback put output selection into
     * first array offset, ie String[0] */
    outProtoArr = (*jenv)->NewObjectArray(jenv, 1,
        (*jenv)->FindClass(jenv, "java/lang/String"), NULL);
    if (outProtoArr == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Failed to create JNI String[1] for output ALPN protocol");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    /* call Java callback */
    ret = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
       alpnSelectMethodId, (jobject)(*g_cachedSSLObj), outProtoArr,
       peerProtosArr);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->ThrowNew(jenv, excClass,
            "Exception while calling internalAlpnSelectCallback()");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (ret == SSL_TLSEXT_ERR_OK) {
        /* convert returned String[0] into char* */
        outProtoArrSz = (*jenv)->GetArrayLength(jenv, outProtoArr);
        if (outProtoArrSz != 1) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }
            (*jenv)->ThrowNew(jenv, excClass,
                "Output String[] for ALPN result not size 1");
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        /* get jstring from String[0] */
        selectedProto = (jstring)(*jenv)->GetObjectArrayElement(
            jenv, outProtoArr, 0);
        if (selectedProto == NULL) {
            if ((*jenv)->ExceptionOccurred(jenv)) {
                (*jenv)->ExceptionDescribe(jenv);
                (*jenv)->ExceptionClear(jenv);
            }
            (*jenv)->ThrowNew(jenv, excClass,
                "Selected ALPN protocol in String[] is NULL");
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        /* get char* from jstring */
        selectedProtoCharArr = (*jenv)->GetStringUTFChars(jenv,
            selectedProto, 0);
        selectedProtoCharArrSz = (int)XSTRLEN(selectedProtoCharArr);

        /* see if selected ALPN protocol is in original sent list */
        if (selectedProtoCharArr != NULL) {
            for (idx = 0; idx < inlen; idx++) {
                if (idx + selectedProtoCharArrSz > inlen) {
                    /* No match found, fatal error. in not long enough for
                     * search. Reset ret to error condition, match not set
                     * correctly */
                    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
                    break;
                }
                if (XMEMCMP(in + idx, selectedProtoCharArr,
                        selectedProtoCharArrSz) == 0) {
                    /* Match found. Format of input array is length byte of
                     * ALPN protocol, followed by ALPN protocol,
                     * ie (LEN+ALPN|LEN+ALPN|...) We set *out to ALPN selected
                     * protocol and *outlen to length of protocol (idx - 1) */
                    *out = in + idx;
                    *outlen = in[idx - 1];
                    break;
                }
            }
        }
        else {
            /* Not able to get selected ALPN protocol from Java, fatal error */
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
        }
    }

   return ret;
}

#endif /* HAVE_ALPN */

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_keepArrays
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    (void)jenv;
    (void)jcl;
#ifndef WOLFCRYPT_ONLY
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;

    /* Checks ssl for null internally */
    wolfSSL_KeepArrays(ssl);
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLSession_getClientRandom
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if !defined(WOLFCRYPT_ONLY) && (defined(OPENSSL_EXTRA) || \
    defined(WOLFSSL_WPAS_SMALL) || defined(HAVE_SECRET_CALLBACK)) && \
    !defined(NO_WOLFSSL_CLIENT)
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    int clientRandomSz;
    byte clientRandom[32];
    jbyteArray randomArr = NULL;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return NULL;
    }

    clientRandomSz = (int)wolfSSL_get_client_random(ssl, clientRandom,
        sizeof(clientRandom));

    if (clientRandomSz <= 0) {
        return NULL;
    }

    randomArr = (*jenv)->NewByteArray(jenv, clientRandomSz);
    if (randomArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native getClientRandom()");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, randomArr, 0, clientRandomSz,
        (jbyte*)clientRandom);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return randomArr;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;

    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_setTls13SecretCb
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
#if defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    defined(HAVE_SECRET_CALLBACK)
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    int ret = SSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Java layer handles setting and giving back user CTX */
    ret = wolfSSL_set_tls13_secret_cb(ssl, NativeTls13SecretCb, NULL);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    return NOT_COMPILED_IN;
#endif
}

#if defined(WOLFSSL_TLS13) && !defined(WOLFCRYPT_ONLY) && \
    defined(HAVE_SECRET_CALLBACK)

int NativeTls13SecretCb(WOLFSSL *ssl, int id, const unsigned char* secret,
    int secretSz, void* ctx)
{
    JNIEnv* jenv;                   /* JNI environment */
    jclass  excClass;               /* WolfSSLJNIException class */
    int     needsDetach = 0;        /* Should we explicitly detach? */
    jint    retval = 0;
    jint    vmret = 0;

    jobject*  g_cachedSSLObj;       /* WolfSSLSession cached object */
    jclass    sslClass;             /* WolfSSLSession class */
    jmethodID tls13SecretMethodId;  /* internalTls13SecretCallback ID */
    jbyteArray secretArr = NULL;

    if (g_vm == NULL || ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return TLS13_SECRET_CB_E;
        }
        needsDetach = 1;
    }
    else if (vmret != JNI_OK) {
        return TLS13_SECRET_CB_E;
    }

    /* Find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return TLS13_SECRET_CB_E;
    }

    /* Get stored WolfSSLSession object */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession object reference in "
            "NativeTls13SecretCb");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return TLS13_SECRET_CB_E;
    }

    /* Lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (sslClass == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference in "
            "NativeTls13SecretCb");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return TLS13_SECRET_CB_E;
    }

    /* Call internal TLS 1.3 secret callback */
    tls13SecretMethodId = (*jenv)->GetMethodID(jenv, sslClass,
        "internalTls13SecretCallback", "(Lcom/wolfssl/WolfSSLSession;I[B)I");
    if (tls13SecretMethodId == NULL) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalTls13SecretCallback method from JNI");
        if (needsDetach) {
            (*g_vm)->DetachCurrentThread(g_vm);
        }
        return TLS13_SECRET_CB_E;
    }

    if (secretSz > 0) {
        /* Create jbyteArray to hold secret data */
        secretArr = (*jenv)->NewByteArray(jenv, secretSz);
        if (secretArr == NULL) {
            (*jenv)->ThrowNew(jenv, excClass,
                "Error creating new jbyteArray in NativeTls13SecretCb");
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return TLS13_SECRET_CB_E;
        }

        (*jenv)->SetByteArrayRegion(jenv, secretArr, 0, secretSz,
            (jbyte*)secret);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return TLS13_SECRET_CB_E;
        }

        /* Call Java TLS 1.3 secret callback, ignore native CTX since Java
         * handles it */
        retval = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
            tls13SecretMethodId, (jobject)(*g_cachedSSLObj), (jint)id,
            secretArr);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->ThrowNew(jenv, excClass,
                "Exception while calling internalTls13SecretCallback()");
            if (needsDetach) {
                (*g_vm)->DetachCurrentThread(g_vm);
            }
            return TLS13_SECRET_CB_E;
        }

        /* Delete local refs */
        (*jenv)->DeleteLocalRef(jenv, secretArr);
    }

    /* Detach JNIEnv from thread */
    if (needsDetach) {
        (*g_vm)->DetachCurrentThread(g_vm);
    }

    return (int)retval;
}

#endif /* WOLFSSL_TLS13 && !WOLFCRYPT_ONLY && HAVE_SECRET_CALLBACK */

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSecureRenegotiation
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;
#ifdef HAVE_SECURE_RENEGOTIATION
    return (jint)wolfSSL_UseSecureRenegotiation((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_rehandshake
  (JNIEnv* jenv, jobject jcl, jlong ssl)
{
    (void)jenv;
    (void)jcl;
#ifdef HAVE_SECURE_RENEGOTIATION
    return (jint)wolfSSL_Rehandshake((WOLFSSL*)(uintptr_t)ssl);
#else
    (void)ssl;
    return NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_set1SigAlgsList
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jstring list)
{
#ifdef OPENSSL_EXTRA
    int ret = 0;
    const char* sigAlgList = NULL;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL || list == NULL) {
        return SSL_FAILURE;
    }

    sigAlgList = (*jenv)->GetStringUTFChars(jenv, list, 0);

    ret = wolfSSL_set1_sigalgs_list(ssl, sigAlgList);

    (*jenv)->ReleaseStringUTFChars(jenv, list, sigAlgList);

    return (jint)ret;
#else
    (void)jenv;
    (void)ssl;
    (void)list;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_useSupportedCurve
  (JNIEnv* jenv, jobject jcl, jlong sslPtr, jint name)
{
#ifdef HAVE_SUPPORTED_CURVES
    int ret = 0;
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    if (jenv == NULL || ssl == NULL) {
        return (jint)SSL_FAILURE;
    }

    ret = wolfSSL_UseSupportedCurve(ssl, (word16)name);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)sslPtr;
    (void)name;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLSession_hasTicket
  (JNIEnv* jenv, jobject jcl, jlong sessionPtr)
{
#if !defined(NO_SESSION_CACHE) && \
    (defined(OPENSSL_EXTRA) || defined(HAVE_EXT_CACHE))
    WOLFSSL_SESSION* session = (WOLFSSL_SESSION*)(uintptr_t)sessionPtr;
    (void)jcl;

    if (jenv == NULL || session == NULL) {
        return WOLFSSL_FAILURE;
    }

    return (jint)wolfSSL_SESSION_has_ticket((const WOLFSSL_SESSION*)session);
#else
    (void)jenv;
    (void)jcl;
    (void)sessionPtr;
    return (jint)WolfSSL.SSL_FAILURE;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIORecv
    (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    (void)jcl;

    /* find exception class */
    jclass excClass = (*jenv)->FindClass(jenv,
            "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return;
    }

    if (ssl != NULL) {
        /* set I/O recv callback */
        wolfSSL_SSLSetIORecv(ssl, NativeSSLIORecvCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IORecv");
    }
}

int NativeSSLIORecvCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    jint       retval = 0;
    jint       vmret  = 0;

    JNIEnv*    jenv;                  /* JNI environment */
    jclass     excClass;              /* WolfSSLJNIException class */
    int        needsDetach = 0;       /* Should we explicitly detach? */

    jobject*   g_cachedSSLObj;        /* WolfSSLSession cached object */
    jclass     sslClass;              /* WolfSSLSession class */
    jmethodID  recvCbMethodId;        /* internalIORecvCallback ID */
    jbyteArray inData;

    if (!g_vm || !ssl || !buf || !ctx) {
        /* can't throw exception yet, just return error */
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        needsDetach = 1;
    } else if (vmret != JNI_OK) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get stored WolfSSLSession jobject */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession object reference in "
                "NativeSSLIORecvCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return 0;
    }

    /* lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference in "
            "NativeSSLIORecvCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call internal I/O recv callback */
    recvCbMethodId = (*jenv)->GetMethodID(jenv, sslClass,
            "internalIOSSLRecvCallback",
            "(Lcom/wolfssl/WolfSSLSession;[BI)I");
    if (!recvCbMethodId) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalIORecvCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* create jbyteArray to hold received data */
    inData = (*jenv)->NewByteArray(jenv, sz);
    if (!inData) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Error getting internalIORecvCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call Java send callback, ignore native ctx since Java
     * handles it */
    retval = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
            recvCbMethodId, (jobject)(*g_cachedSSLObj), inData, (jint)sz);

    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, inData);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* copy jbyteArray into char array */
    if (retval >= 0) {
        (*jenv)->GetByteArrayRegion(jenv, inData, 0, retval,
                (jbyte*)buf);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, inData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
    }

    /* delete local refs, detach JNIEnv from thread */
    (*jenv)->DeleteLocalRef(jenv, inData);
    if (needsDetach)
        (*g_vm)->DetachCurrentThread(g_vm);

    return retval;
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLSession_setSSLIOSend
  (JNIEnv* jenv, jobject jcl, jlong sslPtr)
{
    WOLFSSL* ssl = (WOLFSSL*)(uintptr_t)sslPtr;
    jclass excClass = NULL;
    (void)jcl;

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
    }

    if (ssl != NULL) {
        /* set I/O send callback */
        wolfSSL_SSLSetIOSend(ssl, NativeSSLIOSendCb);

    } else {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input WolfSSLContext object was null when setting IOSend");
    }
}

int NativeSSLIOSendCb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    jint       retval = 0;
    jint       vmret  = 0;

    JNIEnv*    jenv;                  /* JNI environment */
    jclass     excClass;              /* WolfSSLJNIException class */
    int        needsDetach = 0;       /* Should we explicitly detach? */

    jobject*   g_cachedSSLObj;        /* WolfSSLSession cached object */
    jclass     sslClass;              /* WolfSSLSession class */
    jmethodID  sendCbMethodId;        /* internalIOSendCallback ID */
    jbyteArray outData;               /* jbyteArray for data to send */

    if (!g_vm || !ssl || !buf || !ctx) {
        /* can't throw exception yet, just return error */
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get JavaEnv from JavaVM */
    vmret = (int)((*g_vm)->GetEnv(g_vm, (void**) &jenv, JNI_VERSION_1_6));
    if (vmret == JNI_EDETACHED) {
#ifdef __ANDROID__
        vmret = (*g_vm)->AttachCurrentThread(g_vm, &jenv, NULL);
#else
        vmret = (*g_vm)->AttachCurrentThread(g_vm, (void**) &jenv, NULL);
#endif
        if (vmret) {
            return WOLFSSL_CBIO_ERR_GENERAL;
        }
        needsDetach = 1;
    } else if (vmret != JNI_OK) {
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* find exception class in case we need it */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* get stored WolfSSLSession jobject */
    g_cachedSSLObj = (jobject*) wolfSSL_get_jobject(ssl);
    if (!g_cachedSSLObj) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Can't get native WolfSSLSession object reference in "
                "NativeSSLIOSendCb");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return 0;
    }

    /* lookup WolfSSLSession class from object */
    sslClass = (*jenv)->GetObjectClass(jenv, (jobject)(*g_cachedSSLObj));
    if (!sslClass) {
        (*jenv)->ThrowNew(jenv, excClass,
            "Can't get native WolfSSLSession class reference");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    /* call internal I/O send callback */
    sendCbMethodId = (*jenv)->GetMethodID(jenv, sslClass,
            "internalIOSSLSendCallback",
            "(Lcom/wolfssl/WolfSSLSession;[BI)I");
    if (!sendCbMethodId) {
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
        }
        (*jenv)->ThrowNew(jenv, excClass,
                "Error getting internalIOSendCallback method from JNI");
        if (needsDetach)
            (*g_vm)->DetachCurrentThread(g_vm);
        return WOLFSSL_CBIO_ERR_GENERAL;
    }

    if (sz >= 0)
    {
        /* create jbyteArray to hold received data */
        outData = (*jenv)->NewByteArray(jenv, sz);
        if (!outData) {
            (*jenv)->ThrowNew(jenv, excClass,
                    "Error getting internalIOSendCallback method from JNI");
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        (*jenv)->SetByteArrayRegion(jenv, outData, 0, sz, (jbyte*)buf);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, outData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* call Java send callback, ignore native ctx since Java
         * handles it */
        retval = (*jenv)->CallIntMethod(jenv, (jobject)(*g_cachedSSLObj),
            sendCbMethodId, (jobject)(*g_cachedSSLObj), outData, (jint)sz);

        if ((*jenv)->ExceptionOccurred(jenv)) {
            (*jenv)->ExceptionDescribe(jenv);
            (*jenv)->ExceptionClear(jenv);
            (*jenv)->DeleteLocalRef(jenv, outData);
            if (needsDetach)
                (*g_vm)->DetachCurrentThread(g_vm);
            return WOLFSSL_CBIO_ERR_GENERAL;
        }

        /* delete local refs */
        (*jenv)->DeleteLocalRef(jenv, outData);
    }

    /* detach JNIEnv from thread */
    if (needsDetach)
        (*g_vm)->DetachCurrentThread(g_vm);

    return retval;
}

