/* WolfSSLRsaVerifyCallback.java
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
 * wolfSSL RSA Verification Callback Interface.
 * This interface specifies how applicaitons should implement the RSA
 * verification callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setRsaVerifyCb(WolfSSLRsaVerifyCallback)
 * WolfSSLContext.setRsaVerifyCb()} method to be registered with the native
 * wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLRsaVerifyCallback {

    /**
     * RSA verification callback method.
     * This method acts as RSA verification callback.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param sig       the signature to verify
     * @param sigSz     length of the signature, <b>sig</b>
     * @param out       the verification/output buffer after the decryption
     *                  process and padding.
     * @param outSz     size of the output buffer, <b>out</b>
     * @param keyDer    the RSA Public key in ASN1 format
     * @param keySz     the length of the key, <b>keyDer</b>, in bytes
     * @param ctx       custom user-registered ECC signing context
     * @return          <b><code>0</code></b> upon success,
     *                  otherwise a negative value on error.
     */
    public int rsaVerifyCallback(WolfSSLSession ssl, ByteBuffer sig,
            long sigSz, ByteBuffer out, long outSz, ByteBuffer keyDer,
            long keySz, Object ctx);
}

