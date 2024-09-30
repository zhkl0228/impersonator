/* WolfSSLNativeLoggingCallback.java
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
package com.wolfssl.provider.jsse;

import java.util.Date;
import java.sql.Timestamp;

import com.wolfssl.WolfSSLLoggingCallback;

/**
 * Utility class to help with JSSE-level functionality.
 *
 * Native logging callback class, implements com.wolfssl.WolfSSLLoggingCallback.
 * loggingCallback() method is called by native wolfSSL debug logging
 * mechanism.
 *
 * @author wolfSSL
 */
class WolfSSLNativeLoggingCallback implements WolfSSLLoggingCallback
{
    public synchronized void loggingCallback(int logLevel, String logMessage) {

        System.out.println(new Timestamp(new java.util.Date().getTime()) +
                           " [wolfSSL: TID " +
                           Thread.currentThread().getId() +
                           "] " + logMessage);
    }
}

