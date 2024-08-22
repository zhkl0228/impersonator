/* WolfSSLSocketFactory.java
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
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;

/**
 * wolfSSL implementation of SSLSocketFactory
 *
 * @author wolfSSL
 */
public class WolfSSLSocketFactory extends SSLSocketFactory {

    private WolfSSLAuthStore authStore = null;
    private com.wolfssl.WolfSSLContext ctx = null;
    private com.wolfssl.provider.jsse.WolfSSLContext jsseCtx = null;
    private WolfSSLParameters params;

    /* Defer creation and initialization of DEFAULT Context until used,
     * to remove creation logic from constructor */
    private int isDefault = 0;
    private int isDefaultInitialized = 0;

    /**
     * Create new WolfSSLSocketFactory object with default settings
     *
     * This constructor is used when the JSSE calls
     * SSLSocketFactory.getDefault()
     */
    public WolfSSLSocketFactory() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new default WolfSSLSocketFactory");

        this.isDefault = 1;
        this.isDefaultInitialized = 0;

        /* initialize later on first use */
        this.jsseCtx = null;
        this.ctx = null;
        this.authStore = null;
        this.params = null;
    }

    /**
     * Create new WolfSSLSocketFactory object
     *
     * @param ctx WolfSSLContext object to use with this factory
     * @param authStore WolfSSLAuthStore object to use with this factory
     * @param params WolfSSLParameters to use with this factory
     */
    public WolfSSLSocketFactory(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore authStore, WolfSSLParameters params) {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "created new WolfSSLSocketFactory");

        this.ctx = ctx;
        this.authStore = authStore;
        this.params = params;
    }

    /**
     * Private internal function to create and initialize default context
     * and set ctx, authStore, and params from it.
     * @throws WolfSSLException if default CTX is null
     */
    private void initDefaultContext() throws WolfSSLException {
        if (this.isDefault == 1 && this.isDefaultInitialized == 0) {

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "creating and initializing DEFAULT_Context");

            this.jsseCtx =
                new com.wolfssl.provider.jsse.WolfSSLContext.DEFAULT_Context();
            this.ctx = jsseCtx.getInternalWolfSSLContext();
            if (this.ctx == null) {
                throw new WolfSSLException("Issue with null internal TLS CTX");
            }

            this.authStore = jsseCtx.getInternalAuthStore();
            this.params = jsseCtx.getInternalSSLParams();

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "DEFAULT_Context created and initialized");
        }
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
     * Creates a new unconnected SSLSocket
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    @Override
    public Socket createSocket() throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket()");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params, true);
    }

    /**
     * Creates a new Socket connected to the specified host and port.
     *
     * @param host server host name for Socket to be connected to, or null
     *             for loopback address
     * @param port server port
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    @Override
    public Socket createSocket(InetAddress host, int port)
        throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(InetAddress host, int port)");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params, true, host, port);
    }

    /**
     * Creates a new Socket connected to the specified remote host and port,
     * and also bound to the specified local address and port.
     *
     * @param address server host name for Socket to be connected to, or null
     *                for loopback address
     * @param port server port
     * @param localAddress local address that the Socket will be bound to
     * @param localPort local port that the Socket will be bound to
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    @Override
    public Socket createSocket(InetAddress address, int port,
        InetAddress localAddress, int localPort) throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(InetAddress host, port: " + port + ", " +
            "InetAddress localAddress, localPort: " + localPort + ")");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params,
            true, address, port, localAddress, localPort);
    }

    /**
     * Creates a new Socket connected to the specified host and port.
     *
     * @param host server host name for Socket to be connected to, or null
     *             for loopback address
     * @param port server port
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    @Override
    public Socket createSocket(String host, int port)
        throws IOException, UnknownHostException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(host: " + host + ", port: " + port + ")");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params, true, host, port);
    }

    /**
     * Creates a new Socket connected to the specified remote host and port,
     * and also bound to the specified local address and port.
     *
     * @param host server host name for Socket to be connected, or null for
     *             loopback address
     * @param port server port
     * @param localHost local address that the Socket will be bound to
     * @param localPort local port that the Socket will be bound to
     *
     * @return the new Socket
     * @throws IOException if socket creation fails.
     */
    @Override
    public Socket createSocket(String host, int port, InetAddress localHost,
        int localPort) throws IOException, UnknownHostException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(host: " + host + ", port: " + port +
            ", InetAddress localHost, localPort: " + localPort + ")");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params,
            true, host, port, localHost, localPort);
    }

    /**
     * Creates a new SSLSocket layered over an existing Socket connected to the
     * specified host and port.
     *
     * @param s connected Socket to host
     * @param host host that the Socket is connected to
     * @param port port that the Socket is connected to
     * @param autoClose flag indicating if the underlying Socket should be
     *                  closed when the SSLSocket is closed
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    @Override
    public Socket createSocket(Socket s, String host, int port,
        boolean autoClose) throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(Socket: " + s.getClass() + ", host: " +
            host + ", port: " + port + ", autoClose: " +
            String.valueOf(autoClose) + ")");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params,
            true, s, host, port, autoClose);
    }

    /**
     * Creates a new SSLSocket layered over an existing connected Socket, and
     * is able to read data that has already been consumed from exising
     * Socket's InputStream.
     *
     * @param s connected Socket to host
     * @param consumed consumed inbound network data that has been read off
     *                 the existing Socket's InputStream. May be null if no
     *                 data has been read.
     * @param autoClose flag indicating if the underlying Socket should be
     *                  closed when the SSLSocket is closed
     *
     * @return the new Socket
     * @throws IOException if socket creation fails
     */
    public Socket createSocket(Socket s, InputStream consumed,
        boolean autoClose) throws IOException {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered createSocket(Socket: " + s.getClass() +
            ", InputStream consumed, autoClose: "
            + String.valueOf(autoClose) + ")");

        try {
            initDefaultContext();
        } catch (WolfSSLException e) {
            throw new IOException(e);
        }

        return new WolfSSLSocket(ctx, authStore, params, s,
            consumed, autoClose);
    }
}

