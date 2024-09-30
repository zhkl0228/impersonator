/* WolfSSLMissingCRLCallback.java
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
 * wolfSSL Missing CRL Callback Interface.
 * This interface specifies how applicaitons should implement the missing
 * CRL callback class to be called by wolfSSL when CRL lookup fails.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to either the {@link WolfSSLSession#setCRLCb(long, WolfSSLMissingCRLCallback)
 * WolfSSLSession.setCRLCb()} method or {@link WolfSSLContext#setCRLCb(long,
 * WolfSSLMissingCRLCallback) WolfSSLContext.setCRLCb()} method, to be
 * registered with the native wolfSSL library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLMissingCRLCallback {

    /**
     * Missing CRL callback method.
     * This method provides the callback to be used when CRL lookup
     * failed during certificate verification.
     *
     * @param url   URL of the CRL which failed to verify during the
     *              certificate verification process.
     */
    public void missingCRLCallback(String url);
}

