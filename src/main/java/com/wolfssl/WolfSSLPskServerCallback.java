/* WolfSSLPskServerCallback.java
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
 * wolfSSL PSK Server Callback Interface.
 * This interface specifies how applications should implement the PSK server
 * callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setPskServerCb(WolfSSLPskServerCallback)
 * WolfSSLContext.setPskServerCallback()} method to be registered with the
 * native wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLPskServerCallback {

    /**
     * PSK server callback method.
     * This method acts as a PSK server callback.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param identity  client identity
     * @param key       server key
     * @param keyMaxLen maximum size in bytes that server key can be
     *
     * @return          length of key in octets or 0 for error
     */
    public long pskServerCallback(WolfSSLSession ssl, String identity,
            byte[] key, long keyMaxLen);
}

