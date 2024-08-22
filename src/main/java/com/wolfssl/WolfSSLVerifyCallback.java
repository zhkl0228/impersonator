/* WolfSSLVerifyCallback.java
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
 * wolfSSL Verify Callback Interface.
 * This interface specifies how applicaitons should implement the verify
 * callback class to be used by wolfSSL during the handshake process.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLContext#setVerify(long, int, WolfSSLVerifyCallback)
 * WolfSSLContext.setVerify()} method to be registered with the native wolfSSL
 * library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLVerifyCallback {

    /**
     * Verify callback method.
     * This method acts as the verify callback to be used during the
     * SSL/TLS handshake. It is called when verification of the peer
     * certificate fails. Note that peer verification must be turned on.
     *
     * @param preverify_ok indicates if verification of the peer certificate
     *                     already passed. 0 if failed, 1 if passed.
     * @param x509StorePtr pointer to the context used for certificate
     *                     chain verification.
     * @return             <code>0</code> if the verification process should
     *                     stop immediately with an error. <code>1</code> if
     *                     the verification process should continue with the
     *                     rest of the handshake.
     */
    public int verifyCallback(int preverify_ok, long x509StorePtr);

}

