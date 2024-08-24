/* WolfSSLEccVerifyCallback.java
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
 * wolfSSL ECC Verification Callback Interface.
 * This interface specifies how applicaitons should implement the ECC
 * verification callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setEccVerifyCb(WolfSSLEccVerifyCallback)
 * WolfSSLContext.setEccVerifyCb()} method to be registered with the native
 * wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLEccVerifyCallback {

    /**
     * ECC verification callback method.
     * This method acts as ECC verification callback.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param sig       signature to verify
     * @param sigSz     length of the signature, <b>sig</b>
     * @param hash      input buffer containing the digest of the message
     * @param hashSz    length in bytes of the hash, <b>hash</b>
     * @param keyDer    the ECC Private key in ASN1 format
     * @param keySz     length of the key, <b>keyDer</b>, in bytes
     * @param result    output variable where the result of verification
     *                  should be stored, <b>1</b> for success, <b>0</b> for
     *                  failure. Use the first element of the array for
     *                  storage.
     * @param ctx       custom user-registered ECC signing context
     * @return          <b><code>0</code></b> upon success,
     *                  otherwise a negative value on error.
     */
    public int eccVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer hash, long hashSz, ByteBuffer keyDer,
            long keySz, int[] result, Object ctx);
}

