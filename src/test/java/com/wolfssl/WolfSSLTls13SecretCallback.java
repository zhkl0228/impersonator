/* WolfSSLTls13SecretCallback.java
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
 * wolfSSL TLS 1.3 Secret Callback Interface.
 * This interface specifies how applications should implement the TLS 1.3
 * secret callback class, to be used by wolfSSL when logging TLS 1.3 secrets.
 * <p>
 * To use this interface, native wolfSSL must be compiled with
 * HAVE_SECRET_CALLBACK defined.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the
 * {@link WolfSSLSession#setTls13SecretCb(WolfSSLTls13SecretCallback, Object)
 * WolfSSLSession.setTls13SecretCb()} method to be registered with the native
 * wolfSSL library.
 */
public interface WolfSSLTls13SecretCallback {

    /**
     * Callback method for printing/saving TLS 1.3 secrets, for use
     * with Wireshark.
     *
     * @param ssl       the current SSL session object from which the
     *                  callback was initiated.
     * @param id        Identifier specifying what type of secret this callback
     *                  is being called with, one of the following:
     *                      WolfSSL.CLIENT_EARLY_TRAFFIC_SECRET
     *                      WolfSSL.EARLY_EXPORTER_SECRET
     *                      WolfSSL.CLIENT_HANDSHAKE_TRAFFIC_SECRET
     *                      WolfSSL.SERVER_HANDSHAKE_TRAFFIC_SECRET
     *                      WolfSSL.CLIENT_TRAFFIC_SECRET
     *                      WolfSSL.SERVER_TRAFFIC_SECRET
     *                      WolfSSL.EXPORTER_SECRET
     * @param secret    Current secret as byte array
     * @param ctx       Optional user context if set
     *
     * @return 0 on success, otherwise negative if callback encounters
     *         an error.
     */
    public int tls13SecretCallback(WolfSSLSession ssl, int id,
        byte[] secret, Object ctx);
}

