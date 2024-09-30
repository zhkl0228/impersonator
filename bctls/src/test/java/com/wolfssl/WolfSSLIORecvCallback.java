/* WolfSSLIORecvCallback.java
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

/**
 * wolfSSL I/O Receive Callback Interface.
 * This interface specifies how applicaitons should implement the I/O receive
 * callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setIORecv(WolfSSLIORecvCallback)
 * WolfSSLContext.setIORecv()} method to be registered with the native wolfSSL
 * library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLIORecvCallback {

    /**
     * I/O receive callback method.
     * This method acts as the I/O receive callback to be used with wolfSSL.
     * This can be registered with an SSL session using the
     * WolfSSLContext#setIORecv(WolfSSLIORecvCallback) method.
     *
     * @param ssl   the current SSL session object from which the callback was
     *              initiated.
     * @param buf   buffer in which the application should place data which
     *              has been received from the peer.
     * @param sz    size of buffer, <b>buf</b>
     * @param ctx   I/O context to be used.
     * @return      the number of bytes read, or an error. For possible error
     *              codes, see the default EmbedRecv() function in
     *              wolfssl_package/src/io.c
     */
    public int receiveCallback(WolfSSLSession ssl, byte[] buf, int sz,
            Object ctx);
}

