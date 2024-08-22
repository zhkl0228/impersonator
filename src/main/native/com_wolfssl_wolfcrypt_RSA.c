/* com_wolfssl_wolfcrypt_RSA.c
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

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/rsa.h>

#include "com_wolfssl_wolfcrypt_RSA.h"

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_RSA_doSign
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jintArray outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    WC_RNG  rng;
    RsaKey  myKey;
    unsigned int idx;
    unsigned int tmpOut;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz  < 0) || (keySz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    /* get output buffer size */
    (*jenv)->GetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);

    wc_InitRng(&rng);
    wc_InitRsaKey(&myKey, NULL);

    idx = 0;

    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaSSL_Sign(inBuf, (unsigned int)inSz, outBuf, tmpOut,
                &myKey, &rng);
        if (ret > 0) {
            /* save and convert to 0 for success */
            tmpOut = ret;
            (*jenv)->SetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);
            ret = 0;
        }
    } else {
        printf("wc_RsaPrivateKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_RSA_doVerify
  (JNIEnv* jenv, jobject jcl, jobject sig, jlong sigSz, jobject out,
   jlong outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    unsigned int idx;
    unsigned char* sigBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((sigSz < 0) || (keySz < 0) || (outSz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    sigBuf = (*jenv)->GetDirectBufferAddress(jenv, sig);
    if (sigBuf == NULL) {
        printf("problem getting sig buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    wc_InitRsaKey(&myKey, NULL);
    idx = 0;

    ret = wc_RsaPublicKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaSSL_Verify(sigBuf, (unsigned int)sigSz, outBuf,
                (unsigned int)outSz, &myKey);
        if (ret < 0) {
            printf("wc_RsaSSL_Verify failed, ret = %d\n", ret);
            return ret;
        }
    } else {
        printf("wc_RsaPublicKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_RSA_doEnc
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jintArray outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    WC_RNG  rng;
    unsigned int idx;
    unsigned int tmpOut;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz  < 0) || (keySz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    /* get output buffer size */
    (*jenv)->GetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&tmpOut);

    wc_InitRng(&rng);
    wc_InitRsaKey(&myKey, NULL);

    idx = 0;

    ret = wc_RsaPublicKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaPublicEncrypt(inBuf, (unsigned int)inSz, outBuf, tmpOut,
                &myKey, &rng);
        if (ret > 0) {
            /* save and convert to 0 for success */
            (*jenv)->SetIntArrayRegion(jenv, outSz, 0, 1, (jint*)&ret);
            ret = 0;
        }
    } else {
        printf("wc_RsaPublicKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_RSA_doDec
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jlong outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    RsaKey  myKey;
    unsigned int idx;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    (void)jcl;

    /* check in and key sz */
    if ((inSz < 0) || (keySz < 0) || (outSz < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    inBuf = (*jenv)->GetDirectBufferAddress(jenv, in);
    if (inBuf == NULL) {
        printf("problem getting in buffer address\n");
        return -1;
    }

    outBuf = (*jenv)->GetDirectBufferAddress(jenv, out);
    if (outBuf == NULL) {
        printf("problem getting out buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    wc_InitRsaKey(&myKey, NULL);
    idx = 0;

    ret = wc_RsaPrivateKeyDecode(keyBuf, &idx, &myKey, (unsigned int)keySz);
    if (ret == 0) {
        ret = wc_RsaPrivateDecrypt(inBuf, (unsigned int)inSz, outBuf,
                (unsigned int)outSz, &myKey);
        if (ret < 0) {
            printf("wc_RsaPrivateDecrypt failed, ret = %d\n", ret);
            return ret;
        }
    } else {
        printf("wc_RsaPrivateKeyDecode failed, ret = %d\n", ret);
    }

    wc_FreeRsaKey(&myKey);

    return ret;
}

