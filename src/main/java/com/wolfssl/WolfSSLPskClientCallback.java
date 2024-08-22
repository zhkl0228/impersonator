/* WolfSSLPskClientCallback.java
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
 * wolfSSL PSK Client Callback Interface.
 * This interface specifies how applications should implement the PSK client
 * callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setPskClientCb(WolfSSLPskClientCallback)
 * WolfSSLContext.setPskClientCallback()} method to be registered with the
 * native wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLPskClientCallback {

    /**
     * PSK client callback method.
     * This method acts as a PSK client callback.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param hint      client hint
     * @param identity  client identity
     * @param idMaxLen  maximum size in characters that identity can be
     * @param key       client key
     * @param keyMaxLen maximum size in bytes that client key can be
     *
     * @return          length of key in octets or 0 for error
     */
    public long pskClientCallback(WolfSSLSession ssl, String hint,
            StringBuffer identity, long idMaxLen, byte[] key,
            long keyMaxLen);
}

