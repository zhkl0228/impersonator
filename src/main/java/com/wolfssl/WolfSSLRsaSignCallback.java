/* WolfSSLRsaSignCallback.java
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

/**
 * wolfSSL RSA Signing Callback Interface.
 * This interface specifies how applicaitons should implement the RSA signing
 * callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setRsaSignCb(WolfSSLRsaSignCallback)
 * WolfSSLContext.setRsaSignCb()} method to be registered with the native
 * wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLRsaSignCallback {

    /**
     * RSA signing callback method.
     * This method acts as RSA signing callback.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param in        input buffer to sign
     * @param inSz      length of the input, <b>in</b>
     * @param out       output buffer where the result of signature should
     *                  be stored.
     * @param outSz     input/output variable that specifies the size of the
     *                  output buffer upon invocation. The actual size of
     *                  the signature should be stored there before
     *                  returning. Use the first element of the array
     *                  for storage.
     * @param keyDer    RSA Private key in ASN1 format
     * @param keySz     length of the key, <b>keyDer</b>, in bytes
     * @param ctx       custom user-registered ECC signing context
     * @return          <b><code>0</code></b> upon success,
     *                  otherwise a negative value on error.
     */
    public int rsaSignCallback(WolfSSLSession ssl, ByteBuffer in, long inSz,
            ByteBuffer out, int[] outSz, ByteBuffer keyDer, long keySz,
            Object ctx);
}

