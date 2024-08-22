/* com_wolfssl_WolfSSLX509Name.c
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

#include <wolfssl/ssl.h>

#include "com_wolfssl_globals.h"
#include "com_wolfssl_WolfSSLX509Name.h"

JNIEXPORT jlong JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1new
  (JNIEnv* jenv, jclass jcl)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509_NAME* x509Name = NULL;
    (void)jcl;

    if (jenv == NULL) {
        return 0;
    }

    x509Name = wolfSSL_X509_NAME_new();
    if (x509Name == NULL) {
        return 0;
    }

    return (jlong)(uintptr_t)x509Name;
#else
    (void)jenv;
    (void)jcl;
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1free
  (JNIEnv* jenv, jclass jcl, jlong x509NamePtr)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509_NAME* ptr = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    (void)jcl;

    if (jenv == NULL || ptr == NULL) {
        return;
    }

    wolfSSL_X509_NAME_free(ptr);
#else
    (void)jenv;
    (void)jcl;
    (void)x509NamePtr;
#endif
}

JNIEXPORT jint JNICALL Java_com_wolfssl_WolfSSLX509Name_X509_1NAME_1add_1entry_1by_1txt
  (JNIEnv* jenv, jclass jcl, jlong x509NamePtr, jstring fieldStr, jint type,
   jbyteArray entryArr, jint entryLen, jint loc, jint set)
{
#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS) && \
    (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
    WOLFSSL_X509_NAME* ptr = (WOLFSSL_X509_NAME*)(uintptr_t)x509NamePtr;
    const char* field = NULL;
    unsigned char* entry = NULL;
    int ret = WOLFSSL_FAILURE;
    int len = 0;
    (void)jcl;
    (void)entryLen;

    if (jenv == NULL) {
        return ret;
    }

    field = (*jenv)->GetStringUTFChars(jenv, fieldStr, 0);
    entry = (unsigned char*)(*jenv)->GetByteArrayElements(jenv, entryArr, NULL);
    len = (*jenv)->GetArrayLength(jenv, entryArr);

    if (entry != NULL && len > 0 && field != NULL) {

        ret = wolfSSL_X509_NAME_add_entry_by_txt(ptr, field, (int)type,
                entry, len, (int)loc, (int)set);
    }

    (*jenv)->ReleaseByteArrayElements(jenv, entryArr, (jbyte*)entry, JNI_ABORT);
    (*jenv)->ReleaseStringUTFChars(jenv, fieldStr, field);

    return (jint)ret;
#else
    (void)jenv;
    (void)jcl;
    (void)x509NamePtr;
    (void)fieldStr;
    (void)type;
    (void)entryArr;
    (void)entryLen;
    (void)loc;
    (void)set;
    return (jint)NOT_COMPILED_IN;
#endif
}

