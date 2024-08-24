/* com_wolfssl_wolfcrypt_ECC.c
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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/asn.h>

#include "com_wolfssl_wolfcrypt_ECC.h"

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_ECC_doVerify
  (JNIEnv* jenv, jobject jcl, jobject sig, jlong sigSz, jobject hash,
   jlong hashSz, jobject keyDer, jlong keySz, jintArray result)
{
    int     ret;
    int     tmpResult;
    ecc_key myKey;
    unsigned char* sigBuf = NULL;
    unsigned char* hashBuf = NULL;
    unsigned char* keyBuf = NULL;

    if ((sigSz  < 0) || (hashSz < 0) || (keySz  < 0)) {
        return -1;
    }

    /* get pointers to our buffers */
    sigBuf = (*jenv)->GetDirectBufferAddress(jenv, sig);
    if (sigBuf == NULL) {
        printf("problem getting sig buffer address\n");
        return -1;
    }

    hashBuf = (*jenv)->GetDirectBufferAddress(jenv, hash);
    if (hashBuf == NULL) {
        printf("problem getting hash buffer address\n");
        return -1;
    }

    keyBuf = (*jenv)->GetDirectBufferAddress(jenv, keyDer);
    if (keyBuf == NULL) {
        printf("problem getting key buffer address\n");
        return -1;
    }

    wc_ecc_init(&myKey);

    ret = wc_ecc_import_x963(keyBuf, (unsigned int)keySz, &myKey);

    if (ret == 0) {
        ret = wc_ecc_verify_hash(sigBuf, (unsigned int)sigSz, hashBuf,
                (unsigned int)hashSz, &tmpResult, &myKey);
        if (ret != 0) {
            printf("wc_ecc_verify_hash failed, ret = %d\n", ret);
            wc_ecc_free(&myKey);
            return -1;
        }
    } else {
        printf("wc_ecc_import_x963 failed, ret = %d\n", ret);
        return -1;
    }

    wc_ecc_free(&myKey);

    (*jenv)->SetIntArrayRegion(jenv, result, 0, 1, &tmpResult);

    (void)jcl;
    return ret;
}

JNIEXPORT jint JNICALL Java_com_wolfssl_wolfcrypt_ECC_doSign
  (JNIEnv* jenv, jobject jcl, jobject in, jlong inSz, jobject out,
   jlongArray outSz, jobject keyDer, jlong keySz)
{
    int     ret;
    WC_RNG  rng;
    ecc_key myKey;
    unsigned int tmpOut;
    unsigned int idx = 0;
    unsigned char* inBuf = NULL;
    unsigned char* outBuf = NULL;
    unsigned char* keyBuf = NULL;
    jlong tmp = 0;

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

    /* set previous value of outSz */
    (*jenv)->GetLongArrayRegion(jenv, outSz, 0, 1, &tmp);
    tmpOut = (unsigned int)tmp;

    wc_InitRng(&rng);
    wc_ecc_init(&myKey);

    ret = wc_EccPrivateKeyDecode(keyBuf, &idx, &myKey, (long)keySz);
    if (ret == 0) {
        ret = wc_ecc_sign_hash(inBuf, (unsigned int)inSz, outBuf, &tmpOut,
                &rng, &myKey);
        if (ret != 0) {
            printf("wc_ecc_sign_hash failed, ret = %d\n", ret);
            wc_ecc_free(&myKey);
            return -1;
        }
    } else {
        printf("wc_EccPrivateKeyDecode failed, ret = %d\n", ret);
        return -1;
    }

    wc_ecc_free(&myKey);

    (*jenv)->SetLongArrayRegion(jenv, outSz, 0, 1, (jlong*)&tmpOut);

    (void)jcl;
    return ret;
}

