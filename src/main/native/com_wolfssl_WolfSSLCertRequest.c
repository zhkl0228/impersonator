/* com_wolfssl_WolfSSLCertRequest.c
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
#include <wolfssl/version.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/openssl/evp.h>    /* for EVP_PKEY functions */
#include <wolfssl/openssl/x509v3.h> /* for WOLFSSL_X509_EXTENSION */
#include <wolfssl/error-ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLCertRequest.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1new
  (JNIEnv* jenv, jclass jcl)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = NULL;
    (void)jcl;

    if (jenv == NULL) {
        return (jlong)0;
    }

    x509 = wolfSSL_X509_REQ_new();
    if (x509 == NULL) {
        return (jlong)0;
    }

    return (jlong)(uintptr_t)x509;
#else
    (void)jenv;
    (void)jcl;
    return (jlong)0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1free
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return;
    }

    wolfSSL_X509_REQ_free(x509);
#else
    (void)jenv;
    (void)jcl;
    return;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1set_1subject_1name
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jlong x509NamePtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    WOLFSSL_X509_NAME* x509Name = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    int ret = WOLFSSL_FAILURE;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || x509Name == NULL) {
        return ret;
    }

    ret = wolfSSL_X509_REQ_set_subject_name(x509, x509Name);

    return ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)x509NamePtr;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1add1_1attr_1by_1NID
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jint nid, jint type, jbyteArray attrBytes)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    int ret = WOLFSSL_SUCCESS;
    unsigned char* attr = NULL;
    int attrSz = 0;
    (void)jcl;

    if (jenv == NULL || x509 == NULL || attrBytes == NULL) {
        return WOLFSSL_FAILURE;
    }

    attr = (byte*)(*jenv)->GetByteArrayElements(jenv, attrBytes, NULL);
    attrSz = (*jenv)->GetArrayLength(jenv, attrBytes);

    if (attr == NULL || attrSz <= 0) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = X509_REQ_add1_attr_by_NID(x509, (int)nid, (int)type,
                attr, attrSz);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, attrBytes, (jbyte*)attr, JNI_ABORT);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)nid;
    (void)type;
    (void)attrBytes;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1set_1version
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jlong version)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    ret = X509_REQ_set_version(x509, (long)version);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)version;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1print
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    defined(OPENSSL_EXTRA) && !defined(NO_BIO) && defined(XSNPRINTF) && \
    defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    WOLFSSL_BIO* bio = NULL;
    char* mem = NULL;
    int sz = 0;
    jbyteArray memArr = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    bio = wolfSSL_BIO_new(wolfSSL_BIO_s_mem());
    if (bio == NULL) {
        return NULL;
    }

    if (wolfSSL_X509_REQ_print(bio, x509) != WOLFSSL_SUCCESS) {
        wolfSSL_BIO_free(bio);
        return NULL;
    }

    sz = wolfSSL_BIO_get_mem_data(bio, &mem);
    if (sz > 0 && mem != NULL) {

        memArr = (*jenv)->NewByteArray(jenv, sz);
        if (memArr == NULL) {
            wolfSSL_BIO_free(bio);
            return NULL;
        }

        (*jenv)->SetByteArrayRegion(jenv, memArr, 0, sz, (jbyte*)mem);
        if ((*jenv)->ExceptionOccurred(jenv)) {
            /* failed to set byte region */
            (*jenv)->DeleteLocalRef(jenv, memArr);
            wolfSSL_BIO_free(bio);
            return NULL;
        }
    }
    wolfSSL_BIO_free(bio);
    return memArr;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1sign
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jint keyType, jbyteArray keyBytes, jint fileFormat, jstring digestAlg)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    byte* keyBuf = NULL;
    byte* derBuf = NULL;
    int keySz = 0;
    int derSz = 0;
    byte derAllocated = 0;
    WOLFSSL_EVP_PKEY* priv = NULL;
    const WOLFSSL_EVP_MD* md = NULL;
    unsigned char* rsaPrivBuf = NULL;
    const char* mdName = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    keyBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, keyBytes, NULL);
    keySz = (*jenv)->GetArrayLength(jenv, keyBytes);

    if (keyBuf == NULL || keySz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    /* Set correct WOLFSSL_EVP_MD, does not need to be freed */
    if (ret == WOLFSSL_SUCCESS) {
        mdName = (*jenv)->GetStringUTFChars(jenv, digestAlg, 0);
        if (mdName == NULL) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            md = wolfSSL_EVP_get_digestbyname(mdName);
            if (md == NULL) {
                ret = WOLFSSL_FAILURE;
            }
        }
    }

    /* convert PEM to DER if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if ((int)fileFormat == WOLFSSL_FILETYPE_ASN1) {
            /* already in DER */
            derBuf = keyBuf;
            derSz = keySz;
        }
        else {
            /* get needed buffer size */
            ret = wc_KeyPemToDer(keyBuf, keySz, NULL, 0, NULL);
            if (ret <= 0) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                derSz = ret;
                derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    ret = WOLFSSL_SUCCESS;
                    derAllocated = 1;
                    XMEMSET(derBuf, 0, derSz);
                }
            }
        }
    }

    /* convert PEM to DER if derBuf has been allocated */
    if (derAllocated == 1 && ret == WOLFSSL_SUCCESS) {
        ret = wc_KeyPemToDer(keyBuf, keySz, derBuf, derSz, NULL);
        if (ret <= 0 || ret != derSz) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    }

    /* convert buffer into WOLFSSL_EVP_PKEY */
    if (ret == WOLFSSL_SUCCESS) {
        rsaPrivBuf = derBuf;

        priv = wolfSSL_d2i_PrivateKey((int)keyType, NULL,
                (const unsigned char**)&rsaPrivBuf, derSz);
        if (priv == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    /* sign WOLFSSL_X509 with WOLFSSL_EVP_PKEY, returns size of signature
     * on success or negative on error */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_REQ_sign(x509, priv, md);
        if (ret >= 0) {
            ret = WOLFSSL_SUCCESS;
        }
    }

    if (priv != NULL) {
        wolfSSL_EVP_PKEY_free(priv);
    }
    if (derAllocated == 1 && derBuf != NULL) {
        XMEMSET(derBuf, 0, derSz);
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (*jenv)->ReleaseByteArrayElements(jenv, keyBytes, (jbyte*)keyBuf,
                                      JNI_ABORT);
    (*jenv)->ReleaseStringUTFChars(jenv, digestAlg, mdName);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)keyType;
    (void)keyBytes;
    (void)fileFormat;
    (void)digestAlg;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1set_1pubkey_1native_1open
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jint keyType, jbyteArray fileBytes, jint fileFormat)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    byte* fileBuf = NULL;
    byte* derBuf = NULL;
    int fileSz = 0;
    int derSz  = 0;
    byte derAllocated = 0;
    WOLFSSL_EVP_PKEY* pub = NULL;
    unsigned char* rsaPubBuf = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    fileBuf = (byte*)(*jenv)->GetByteArrayElements(jenv, fileBytes, NULL);
    fileSz = (*jenv)->GetArrayLength(jenv, fileBytes);

    if (fileBuf == NULL || fileSz == 0) {
        ret = WOLFSSL_FAILURE;
    }

    /* convert PEM to DER if needed */
    if (ret == WOLFSSL_SUCCESS) {
        if ((int)fileFormat == WOLFSSL_FILETYPE_ASN1) {
            /* already in DER */
            derBuf = fileBuf;
            derSz = fileSz;
        }
        else {
            /* get needed buffer size */
            ret = wc_KeyPemToDer(fileBuf, fileSz, NULL, 0, NULL);
            if (ret <= 0) {
                ret = WOLFSSL_FAILURE;
            }
            else {
                derSz = ret;
                derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (derBuf == NULL) {
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    ret = WOLFSSL_SUCCESS;
                    derAllocated = 1;
                    XMEMSET(derBuf, 0, derSz);
                }
            }
        }
    }

    /* convert PEM to DER if derBuf has been allocated */
    if (derAllocated == 1 && ret == WOLFSSL_SUCCESS) {
        ret = wc_KeyPemToDer(fileBuf, fileSz, derBuf, derSz, NULL);
        if (ret <= 0 || ret != derSz) {
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    }

    /* convert buffer into WOLFSSL_EVP_PKEY */
    if (ret == WOLFSSL_SUCCESS) {
        rsaPubBuf = derBuf;

        pub = wolfSSL_d2i_PUBKEY(NULL, (const unsigned char**)&rsaPubBuf, derSz);
        if (pub == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    /* set WOLFSSL_EVP_PKEY into WOLFSSL_X509 */
    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_set_pubkey(x509, pub);
    }

    if (pub != NULL) {
        /* free WOLFSSL_EVP_PKEY, since X509_set_pubkey() makes copy */
        wolfSSL_EVP_PKEY_free(pub);
    }
    if (derAllocated == 1 && derBuf != NULL) {
        XMEMSET(derBuf, 0, derSz);
        XFREE(derBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (*jenv)->ReleaseByteArrayElements(jenv, fileBytes, (jbyte*)fileBuf,
                                      JNI_ABORT);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)keyType;
    (void)fileBytes;
    (void)fileFormat;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1get_1der
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && \
    !defined(NO_BIO)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    unsigned char* der = NULL;
    jbyteArray  derArr = NULL;
    jclass excClass = NULL;
    int sz = 0;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    sz = wolfSSL_i2d_X509_REQ(x509, &der);
    if (sz <= 0) {
        return NULL;
    }

    derArr = (*jenv)->NewByteArray(jenv, sz);
    if (derArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_REQ_get_der");
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, derArr, 0, sz, (jbyte*)der);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, derArr);
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set byte region in native X509_REQ_get_der");
        return NULL;
    }

    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    return derArr;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    return NULL;
#endif
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1REQ_1get_1pem
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_ALL) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_REQ) && \
    !defined(NO_BIO)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    unsigned char* der = NULL;
    unsigned char* pem = NULL;
    int sz = 0;
    int pemSz = 0;
    jbyteArray pemArr = NULL;
    jclass excClass = NULL;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return NULL;
    }

    sz = wolfSSL_i2d_X509_REQ(x509, &der);
    if (sz <= 0) {
        return NULL;
    }

    pemSz = wc_DerToPem(der, sz, NULL, 0, CERTREQ_TYPE);
    if (pemSz < 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }

    pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        return NULL;
    }
    XMEMSET(pem, 0, pemSz);

    pemSz = wc_DerToPem(der, sz, pem, pemSz, CERTREQ_TYPE);
    if (pemSz < 0) {
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    pemArr = (*jenv)->NewByteArray(jenv, pemSz);
    if (pemArr == NULL) {
        (*jenv)->ThrowNew(jenv, jcl,
            "Failed to create byte array in native X509_REQ_get_pem");
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLJNIException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, pemArr);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, pemArr, 0, pemSz, (jbyte*)pem);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        (*jenv)->DeleteLocalRef(jenv, pemArr);
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to set byte region in native X509_get_pem");
        return NULL;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return pemArr;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    return NULL;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1add_1ext_1via_1nconf_1nid
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jint nid, jstring extValue, jboolean isCritical)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    const char* value = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    value = (*jenv)->GetStringUTFChars(jenv, extValue, 0);
    if (value == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        ext = wolfSSL_X509V3_EXT_nconf_nid(NULL, NULL, (int)nid, value);
        if (ext == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (isCritical == JNI_TRUE) {
            ret = wolfSSL_X509_EXTENSION_set_critical(ext, 1);
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
    }

    if (ext != NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
    }

    (*jenv)->ReleaseStringUTFChars(jenv, extValue, value);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)nid;
    (void)extValue;
    (void)isCritical;
    return (jint)NOT_COMPILED_IN;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLCertRequest_X509_1add_1ext_1via_1set_1object_1boolean
  (JNIEnv* jenv, jclass jcl, jlong x509ReqPtr, jint nid, jboolean extValue, jboolean isCritical)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && defined(OPENSSL_EXTRA)
    WOLFSSL_X509* x509 = (WOLFSSL_X509*)(uintptr_t)x509ReqPtr;
    WOLFSSL_X509_EXTENSION* ext = NULL;
    WOLFSSL_ASN1_OBJECT* obj = NULL;
    int ret = WOLFSSL_SUCCESS;
    (void)jcl;

    if (jenv == NULL || x509 == NULL) {
        return WOLFSSL_FAILURE;
    }

    ext = wolfSSL_X509_EXTENSION_new();
    if (ext == NULL) {
        ret = WOLFSSL_FAILURE;
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (isCritical == JNI_TRUE) {
            ret = wolfSSL_X509_EXTENSION_set_critical(ext, 1);
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        obj = wolfSSL_OBJ_nid2obj((int)nid);
        if (obj == NULL) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        if (extValue == JNI_TRUE) {
            obj->ca = 1;
        }
        else {
            obj->ca = 0;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_EXTENSION_set_object(ext, obj);
    }

    if (ret == WOLFSSL_SUCCESS) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
    }


    if (obj != NULL) {
        wolfSSL_ASN1_OBJECT_free(obj);
    }
    if (ext != NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
    }

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509ReqPtr;
    (void)nid;
    (void)extValue;
    (void)isCritical;
    return (jint)NOT_COMPILED_IN;
#endif
}

