/* WolfSSLLoggingCallback.java
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
 * wolfSSL Logging Callback Interface.
 * This interface specifies how applicaitons should implement the logging
 * callback class to be used by wolfSSL for printing debug messages.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSL#setLoggingCb(WolfSSLLoggingCallback)
 * WolfSSL.setLoggingCb()} method to be registered with the native wolfSSL
 * library.
 *
 * @author  wolfSSL
 */
public interface WolfSSLLoggingCallback {

    /**
     * Logging callback method.
     * This method provides the logging callback to be used when
     * printing debug and trace messages from wolfSSL. Note that wolfSSL
     * must have been compiled with debugging enabled.
     *
     * @param logLevel      debug level of the log message
     * @param logMessage    log/debug message to be printed
     */
    public void loggingCallback(int logLevel, String logMessage);
}

