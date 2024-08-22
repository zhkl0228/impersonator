/* WolfSSLServerSocketFactory.java
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

import java.io.IOException;
import java.net.InetAddress;
import javax.net.ssl.SSLServerSocketFactory;
import java.net.ServerSocket;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLContext;

/**
 * wolfSSL implementation of SSLServerSocketFactory
 *
 * @author wolfSSL Inc.
 */
public class WolfSSLServerSocketFactory extends SSLServerSocketFactory {

    private WolfSSLAuthStore authStore = null;
    private WolfSSLContext ctx = null;
    private WolfSSLParameters params;

    /**
     * Create new WolfSSLServerSocketFactory
     *
     * @param ctx WolfSSLContext object to use with this factory
     * @param authStore WolfSSLAuthStore object to use for this factory
     * @param params WolfSSLParameters object to use with this factory
     */
    public WolfSSLServerSocketFactory(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore authStore, WolfSSLParameters params) {
        super();
        this.ctx = ctx;
        this.authStore = authStore;
        this.params = params;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "creating new WolfSSLServerSocketFactory");
    }

    /**
     * Returns the default cipher suite list for wolfJSSE.
     *
     * @return default array of cipher suite Strings for wolfSSL
     */
    @Override
    public String[] getDefaultCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getDefaultCipherSuites()");

        return WolfSSLUtil.sanitizeSuites(WolfSSL.getCiphersIana());
    }

    /**
     * Returns the supported cipher suite list for this factory.
     *
     * @return array of supported cipher suite Strings
     */
    @Override
    public String[] getSupportedCipherSuites() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedCipherSuites()");

        return getDefaultCipherSuites();
    }

    /**
     * Creates a new unbound SSLServerSocket.
     *
     * @return the new ServerSocket
     * @throws IOException if socket creation fails
     */
    @Override
    public ServerSocket createServerSocket() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createServerSocket()");

        return new WolfSSLServerSocket(ctx, authStore, params);
    }

    /**
     * Creates a new SSLServerSocket bound to the specified port.
     *
     * @param port port number on which to bind socket
     *
     * @return the new ServerSocket
     * @throws IOException if socket creation fails.
     */
    @Override
    public ServerSocket createServerSocket(int port) throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createServerSocket(port: " + port + ")");

        return new WolfSSLServerSocket(ctx, authStore, params, port);
    }

    /**
     * Creates a new SSLServerSocket bound to the specified port, using
     * the specified connection backlog.
     *
     * @param port port number on which to bind Socket
     * @param backlog connection backlog for this Socket
     *
     * @return the new ServerSocket
     * @throws IOException if socket creation fails.
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog)
        throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createServerSocket(port: " + port +
            ", backlog: " + backlog + ")");

        return new WolfSSLServerSocket(ctx, authStore, params, port, backlog);
    }

    /**
     * Creates a new SSLServerSocket bound to the specified port, using the
     * specified connection backlog, and using a local IP.
     *
     * @param port port number on which to bind Socket
     * @param backlog connection backlog for this Socket
     * @param ifAddress local address to bind Socket
     *
     * @return the new ServerSocket
     * @throws IOException if socket creation fails.
     */
    @Override
    public ServerSocket createServerSocket(int port, int backlog,
        InetAddress ifAddress) throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createServerSocket(port: " + port +
            ", backlog: " + backlog + ", InetAddress)");

        return new WolfSSLServerSocket(ctx, authStore, params, port,
            backlog, ifAddress);
    }
}

