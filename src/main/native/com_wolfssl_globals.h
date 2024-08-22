/* com_wolfssl_globals.c
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

#include <jni.h>

#ifndef _Included_com_wolfssl_globals
#define _Included_com_wolfssl_globals

/* global JavaVM reference for JNIEnv lookup */
extern JavaVM*  g_vm;

/* struct to hold I/O class, object refs */
typedef struct {
    int active;
    jobject obj;
} internCtx;

unsigned int NativePskClientCb(WOLFSSL* ssl, const char* hint, char* identity,
        unsigned int id_max_len, unsigned char* key, unsigned int max_key_len);
unsigned int NativePskServerCb(WOLFSSL* ssl, const char* identity,
        unsigned char* key, unsigned int max_key_len);

#endif

