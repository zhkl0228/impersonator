/* com_wolfssl_wolfcrypt_EccKey.c
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

#include <stdint.h>
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include "com_wolfssl_wolfcrypt_EccKey.h"

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_EccKey_EccPublicKeyToDer
  (JNIEnv* jenv, jobject jcl, jlong eccKey)
{
    jclass excClass;
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* key = (ecc_key*)(uintptr_t)eccKey;
    word32 resultSz = ECC_BUFSIZE;
    byte result[ECC_BUFSIZE];
    jbyteArray resultArray = NULL;
#endif
    (void)jcl;

    if (!jenv)
        return NULL;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef HAVE_ECC

    if (key == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input ecc_key pointer was null in EccPublicKeyToDer");
        return NULL;
    }

    ret = wc_EccPublicKeyToDer(key, result, resultSz, 1);
    if (ret <= 0) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Native call to wc_EccPublicKeyToDer failed");
        return NULL;
    }
    resultSz = ret;

    /* create byte array to return */
    resultArray = (*jenv)->NewByteArray(jenv, resultSz);
    if (!resultArray) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create new byte array in native EccPublicKeyToDer");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, resultArray, 0, resultSz, (jbyte*)result);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return resultArray;

#else
    (*jenv)->ThrowNew(jenv, excClass,
            "wolfSSL not compiled with HAVE_ECC defined");
    return NULL;
#endif /* HAVE_ECC */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_EccKey_EccPrivateKeyToDer
  (JNIEnv* jenv, jobject jcl, jlong eccKey)
{
    jclass excClass;
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* key = (ecc_key*)(uintptr_t)eccKey;
    word32 resultSz = ECC_BUFSIZE;
    byte result[ECC_BUFSIZE];
    jbyteArray resultArray = NULL;
#endif
    (void)jcl;

    if (!jenv)
        return NULL;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef HAVE_ECC

    if (key == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input ecc_key pointer was null in EccPrivateKeyToDer");
        return NULL;
    }

    ret = wc_EccPrivateKeyToDer(key, result, resultSz);
    if (ret <= 0) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Native call to wc_EccPrivateKeyToDer failed");
        return NULL;
    }
    resultSz = ret;

    /* create byte array to return */
    resultArray = (*jenv)->NewByteArray(jenv, resultSz);
    if (!resultArray) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create new byte array in native EccPrivateKeyToDer");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, resultArray, 0, resultSz, (jbyte*)result);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

    return resultArray;

#else
    (*jenv)->ThrowNew(jenv, excClass,
            "wolfSSL not compiled with HAVE_ECC defined");
    return NULL;
#endif /* HAVE_ECC */
}

JNIEXPORT jbyteArray JNICALL Java_com_wolfssl_wolfcrypt_EccKey_EccPrivateKeyToPKCS8
  (JNIEnv* jenv, jobject jcl, jlong eccKey)
{
    jclass excClass;
#ifdef HAVE_ECC
    int ret = 0;
    ecc_key* key = (ecc_key*)(uintptr_t)eccKey;
    word32 resultSz = ECC_BUFSIZE;
    byte* result;
    jbyteArray resultArray = NULL;
#endif
    (void)jcl;

    if (!jenv)
        return NULL;

    /* find exception class */
    excClass = (*jenv)->FindClass(jenv, "com/wolfssl/WolfSSLException");
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        return NULL;
    }

#ifdef HAVE_ECC

    if (key == NULL) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Input ecc_key pointer was null in EccPrivateKeyToPKCS8");
        return NULL;
    }

    /* allocate buffer to hold PKCS8 key */
    ret = wc_EccPrivateKeyToPKCS8(key, NULL, &resultSz);
    if (ret != LENGTH_ONLY_E) {
        (*jenv)->ThrowNew(jenv, excClass,
                "Error getting PKCS8 key length in EccPrivateKeyToPKCS8");
        return NULL;
    }

   result = (byte*)XMALLOC(resultSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
   if (result == NULL) {
       (*jenv)->ThrowNew(jenv, excClass,
               "Error allocating memory for PKCS8 key buffer");
       return NULL;
   }

    ret = wc_EccPrivateKeyToPKCS8(key, result, &resultSz);
    if (ret <= 0) {
        XFREE(result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        (*jenv)->ThrowNew(jenv, excClass,
                "Native call to wc_EccPrivateKeyToDer failed");
        return NULL;
    }
    resultSz = ret;

    /* create byte array to return */
    resultArray = (*jenv)->NewByteArray(jenv, resultSz);
    if (!resultArray) {
        XFREE(result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        (*jenv)->ThrowNew(jenv, excClass,
                "Failed to create new byte array in native EccPrivateKeyToPKCS8");
        return NULL;
    }

    (*jenv)->SetByteArrayRegion(jenv, resultArray, 0, resultSz, (jbyte*)result);
    if ((*jenv)->ExceptionOccurred(jenv)) {
        (*jenv)->ExceptionDescribe(jenv);
        (*jenv)->ExceptionClear(jenv);
        XFREE(result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }

    XFREE(result, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return resultArray;

#else
    (*jenv)->ThrowNew(jenv, excClass,
            "wolfSSL not compiled with HAVE_ECC defined");
    return NULL;
#endif /* HAVE_ECC */
}

