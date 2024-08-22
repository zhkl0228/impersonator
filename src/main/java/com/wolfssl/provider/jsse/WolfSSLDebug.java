/* WolfSSLDebug.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLLoggingCallback;

/**
 * Central location for all debugging messages
 *
 * This class is used internally for displaying debug message.
 *
 * @author wolfSSL
 */
public class WolfSSLDebug {

    /**
     * boolean to check if debug mode is on
     */
    public static final boolean DEBUG = checkProperty();

    /**
     * Error level debug message
     */
    public static final String ERROR = "ERROR";

    /**
     * Info level debug message
     */
    public static final String INFO = "INFO";

    /**
     * Native wolfSSL logging callback.
     * Used to print native wolfSSL debug logs when 'wolfssl.debug' System
     * property is set to "true".
     */
    private static WolfSSLNativeLoggingCallback nativeLogCb = null;

    private static boolean checkProperty() {

        String enabled = System.getProperty("wolfjsse.debug");

        if ((enabled != null) && (enabled.equalsIgnoreCase("true"))) {
            return true;
        }

        return false;
    }

    /**
     * Prints out a message to the console
     * @param string message to be printed
     */
    public static void print(String string) {
        System.out.println("wolfJSSE: " + string);
    }

    /**
     * Checks if debugging is turned on and prints out the message.
     *
     * @param cl class being called from to get debug info
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param string message to be printed out
     */
    public static synchronized void log(Class cl, String tag, String string) {
        if (DEBUG) {
            System.out.println(new Timestamp(new java.util.Date().getTime()) +
                               " [wolfJSSE " + tag + ": TID " +
                               Thread.currentThread().getId() + ": " +
                               cl.getSimpleName() + "] " + string);
        }
    }

    /**
     * Print out a byte array in hex if debugging is enabled.
     *
     * @param cl class this method is being called from
     * @param tag level of debug message i.e. WolfSSLDebug.INFO
     * @param label label string to print with hex
     * @param in byte array to be printed as hex
     * @param sz number of bytes from in array to be printed
     */
    public static synchronized void logHex(Class cl, String tag, String label,
                                           byte[] in, int sz) {
        if (DEBUG) {
            int i = 0, j = 0;
            int printSz = 0;
            long tid = Thread.currentThread().getId();
            String clName = null;

            if (cl == null || in == null || sz == 0) {
                return;
            }
            clName = cl.getSimpleName();
            printSz = Math.min(in.length, sz);

            System.out.print("[wolfJSSE " + tag + ": TID " + tid + ": " +
                             clName + "] " + label + " [" + sz + "]: ");
            for (i = 0; i < printSz; i++) {
                if ((i % 16) == 0) {
                    System.out.printf("\n[wolfJSSE " + tag + ": TID " +
                                      tid + ": " + clName + "] %06X", j * 8);
                    j++;
                }
                System.out.printf(" %02X ", in[i]);
            }
            System.out.println("");
        }
    }

    /**
     * Enable native wolfSSL debug logging based on value of the
     * 'wolfssl.debug' System property.
     *
     * Native wolfSSL must ben compiled with "--enable-debug" or
     * DEBUG_WOLFSSL defined in order for debug logs to print.
     */
    protected static synchronized void setNativeWolfSSLDebugging() {

        String wolfsslDebug = System.getProperty("wolfssl.debug");

        if ((wolfsslDebug != null) && (wolfsslDebug.equalsIgnoreCase("true"))) {

            WolfSSL.debuggingON();
        }

        /* Register our default logging callback for native wolfSSL logs */
        setDefaultNativeLoggingCallback();
    }

    /**
     * Register default native wolfSSL logging callback.
     * Default callback class is WolfSSLNativeLoggingCallback. This could be
     * modified in the future to allow a custom user-registerable callback.
     */
    protected static synchronized void setDefaultNativeLoggingCallback() {

        /* Only create one logging callback object */
        if (nativeLogCb == null) {
            nativeLogCb = new WolfSSLNativeLoggingCallback();
        }

        WolfSSL.setLoggingCb(nativeLogCb);
    }
}

