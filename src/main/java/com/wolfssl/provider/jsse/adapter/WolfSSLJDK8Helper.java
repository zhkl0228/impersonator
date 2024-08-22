/* WolfSSLJDK8Helper.java
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

import java.util.List;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SNIHostName;

/**
 * This class contains functionality that was added as of JDK 1.8, and is
 * isolated in this class as to more easily avoid pre-JDK 1.8 execution from
 * loading this class. Otherwise, importing the classes that did not exist
 * on older JDKs would fail.
 *
 * Execution should be prevented from calling functions in this class on
 * JDK version less than 1.8.
 */
public class WolfSSLJDK8Helper
{
    /** Default WolfSSLJDK8Helper constructor */
    public WolfSSLJDK8Helper() { }

    /**
     * Call SSLParameters.setServerNames() to set SNI server names from
     * WolfSSLParameters into SSLParameters.
     *
     * @param out SSLParameters object to set SNI names into
     * @param m Java method to call to set SNI server names
     * @param in WolfSSLParameters to set SNI names from
     */
    protected static void setServerNames(final SSLParameters out,
                                         final Method m, WolfSSLParameters in) {

        if (out == null || m == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.setServerNames() cannot be null");
        }

        List<WolfSSLSNIServerName> wsni = in.getServerNames();
        if (wsni != null) {
            /* convert WolfSSLSNIServerName list to SNIServerName */
            final ArrayList<SNIServerName> sni =
                new ArrayList<SNIServerName>(wsni.size());
            for (WolfSSLSNIServerName name : wsni) {
                sni.add(new SNIHostName(name.getEncoded()));
            }

            /* call SSLParameters.setServerName() */
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    try {
                        m.invoke(out, sni);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    return null;
                }
            });
        }
    }

    /**
     * Call SSLParameters.getServerNames() to set SNI server names from
     * SSLParameters into WolfSSLParameters.
     *
     * @param in input SSLParameters to read SNI names from
     * @param out WolfSSLParameters to store SNI names into
     */
    protected static void getServerNames(final SSLParameters in,
                                         WolfSSLParameters out) {

        if (out == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.getServerNames() cannot be null");
        }

        List<SNIServerName> sni = in.getServerNames();
        if (sni != null) {
            /* convert SNIServerName list to WolfSSLSNIServerName */
            final ArrayList<WolfSSLSNIServerName> wsni =
                new ArrayList<WolfSSLSNIServerName>(sni.size());
            for (SNIServerName name : sni) {
                wsni.add(new WolfSSLGenericHostName(name.getType(),
                         name.getEncoded()));
            }

            /* call WolfSSLParameters.setServerNames() */
            out.setServerNames(wsni);
        }
    }

    /**
     * Call SSLParameters.setApplicationProtocols() to set ALPN protocols from
     * WolfSSLParameters into SSLParameters.
     *
     * @param out output SSLParameters to store ALPN protocols into
     * @param m method to invoke to set protocols
     * @param in input WolfSSLParameters to read ALPN protocols from
     */
    protected static void setApplicationProtocols(final SSLParameters out,
                                         final Method m, WolfSSLParameters in) {

        if (out == null || m == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.setApplicationProtocols() cannot be null");
        }

        final String[] appProtos = in.getApplicationProtocols();
        final Object[] appProtoArr = {appProtos};
        if (appProtos != null) {
            /* call SSLParameters.setApplicationProtocols() */
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    try {
                        m.invoke(out, appProtoArr);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    return null;
                }
            });
        }
    }

    /**
     * Call SSLParameters.getApplicationProtocols() to get ALPN protocols from
     * SSLParameters into WolfSSLParameters.
     *
     * @param in input SSLParameters to read ALPN protocols from
     * @param out output WolfSSLParameters to store ALPN protocols into
     */
    protected static void getApplicationProtocols(final SSLParameters in,
                                         WolfSSLParameters out) {

        if (out == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.getApplicationProtocols() cannot be null");
        }

        try {
            /* Android API < 29 does not support SSLParameters
             * getApplicationProtocols(). Use reflection here to conditionally
             * call it if available */
            Method meth = SSLParameters.class.getMethod(
                "getApplicationProtocols");
            if (meth == null) {
                return;
            }
            String[] appProtos = (String[])meth.invoke(in);
            if (appProtos != null) {
                /* call WolfSSLParameters.setApplicationProtocols() */
                out.setApplicationProtocols(appProtos);
            }
        } catch (NoSuchMethodException | IllegalAccessException |
                 InvocationTargetException e) {
            /* getApplicationProtocols() not available, just return */
            return;
        }
    }

    /**
     * Call SSLParameters.setEndpointIdentificationAlgorithm() to set
     * Endpoint Identification algo from WolfSSLParameters into
     * SSLParameters.
     *
     * @param out output SSLParameters to store endpoint ID algo into
     * @param m method to invoke to set endpoint ID algo
     * @param in input WolfSSLParameters to read endpoint ID algo from
     */
    protected static void setEndpointIdentificationAlgorithm(
        final SSLParameters out, final Method m, WolfSSLParameters in) {

        if (out == null || m == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.setEndpointIdentificationAlgorithm() " +
                "cannot be null");
        }

        final String idAlgo = in.getEndpointIdentificationAlgorithm();
        if (idAlgo != null) {
            /* call SSLParameters.setEndpointIdentificationAlgorithm() */
            AccessController.doPrivileged(new PrivilegedAction<Object>() {
                public Object run() {
                    try {
                        m.invoke(out, idAlgo);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    return null;
                }
            });
        }
    }

    /**
     * Call SSLParameters.getEndpointIdentificationAlgorithm() to get
     * Endpoint Identification Algorithm from SSLParameters into
     * WolfSSLParameters.
     *
     * @param in input SSLParameters to read Endpoint ID algo from
     * @param out output WolfSSLParameters to store Endpoint ID algo into
     */
    protected static void getEndpointIdentificationAlgorithm(
        final SSLParameters in, WolfSSLParameters out) {

        if (out == null || in == null) {
            throw new NullPointerException("input arguments to " +
                "WolfSSLJDK8Helper.getEndpointIdentificationAlgorithm() " +
                "cannot be null");
        }

        String idAlgo = in.getEndpointIdentificationAlgorithm();
        if (idAlgo != null) {
            /* call WolfSSLParameters.setEndpointIdentificationAlgorithm() */
            out.setEndpointIdentificationAlgorithm(idAlgo);
        }
    }
}

