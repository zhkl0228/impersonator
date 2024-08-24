/* WolfSSLEccSharedSecretCallback.java
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
import com.wolfssl.wolfcrypt.EccKey;

/**
 * wolfSSL ECC Shared Secret Callback Interface.
 * This interface specifies how applicaitons should implement the ECC shared
 * secret callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setEccSharedSecretCb(WolfSSLEccSharedSecretCallback)
 * WolfSSLContext.setEccSharedSecretCb()} method to be registered with the
 * native wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLEccSharedSecretCallback {

    /**
     * ECC shared secret callback method.
     * This method acts as ECC shared secret callback.
     *
     * @param ssl         the current SSL session object from which the
     *                    callback was initiated.
     * @param otherKey    Other ECC key. On client side, holds other public
     *                    key. On server side, holds private key.
     * @param pubKeyDer   On client side, output for client to write public key.
     *                    On server side, input as DER-encoded peer public key.
     * @param pubKeyDerSz On client side, the size of the public key written
     *                    to pubKeyDer should be placed in the first element
     *                    of the array.
     * @param out         Output where shared secret to be placed.
     * @param outSz       Output variabe, the callback should place the size
     *                    of data written to the out array in the first element
     *                    of outSz.
     * @param side        represents side being called from. Either
     *                    WolfSSL.WOLFSSL_CLIENT_END or
     *                    WolfSSL.WOLFSSL_SERVER_END.
     * @param ctx         custom user-registered ECC shared secret context
     * @return            <b><code>0</code></b> upon success,
     *                    otherwise a negative value on error.
     */
    public int eccSharedSecretCallback(WolfSSLSession ssl, EccKey otherKey,
            ByteBuffer pubKeyDer, long[] pubKeyDerSz, ByteBuffer out,
            long[] outSz, int side, Object ctx);
}

