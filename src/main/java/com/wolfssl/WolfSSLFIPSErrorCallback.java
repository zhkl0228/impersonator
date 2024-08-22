/* WolfSSLFIPSErrorCallback.java
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
 * wolfSSL/wolfCrypt FIPS Error Interface.
 * This interface specifies how applications should implement the wolfCrypt
 * FIPS error callback, which will be called if the FIPS self tests fail,
 * including if the power-on integrtiy check verifyCore comparison fails.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSL#setFIPSCb(WolfSSLFIPSErrorCallback)
 * WolfSSL.setFIPSCb()} method to be registered with the native wolfSSL
 * library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLFIPSErrorCallback {

    /**
     * wolfCrypt FIPS error callback.
     * This method is called when wolfCrypt FIPS power-on self tests fail,
     * and can be used to retreive the correct FIPS verifyCore hash that
     * needs to be updated in the native ./wolfcrypt/src/fips_test.c file.
     *
     * @param ok    FIPS status ok, 0 for not ok, 1 for ok
     * @param err   wolfCrypt FIPS error code
     * @param hash  Expected wolfCrypt FIPS verifyCore hash value
     */
    public void errorCallback(int ok, int err, String hash);
}

