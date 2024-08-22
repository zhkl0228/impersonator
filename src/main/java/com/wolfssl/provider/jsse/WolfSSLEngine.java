/* WolfSSLEngine.java
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

import com.wolfssl.WolfSSL;
import com.wolfssl.WolfSSLException;
import com.wolfssl.WolfSSLIORecvCallback;
import com.wolfssl.WolfSSLIOSendCallback;
import com.wolfssl.WolfSSLJNIException;
import com.wolfssl.WolfSSLSession;
import com.wolfssl.WolfSSLALPNSelectCallback;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.function.BiFunction;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.cert.CertificateEncodingException;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLParameters;
import java.net.SocketException;
import java.net.SocketTimeoutException;

/**
 * wolfSSL implementation of SSLEngine.
 *
 * There is more verbose debugging available for this class apart
 * from the normal 'wolfjsse.debug' logging. To enable more verbose
 * logging use both the following system properties:
 *
 * System.setProperty("wolfjsse.debug", "true");
 * System.setProperty("wolfsslengine.debug", "true");
 *
 * This will add extra debug logs around wrap() and unwrap() calls, as well
 * as printing out the data sent/received in the I/O callbacks.
 *
 * @author wolfSSL
 */
public class WolfSSLEngine extends SSLEngine {

    private WolfSSLEngineHelper engineHelper = null;
    private WolfSSLSession ssl = null;
    private com.wolfssl.WolfSSLContext ctx = null;
    private WolfSSLAuthStore authStore = null;
    private WolfSSLParameters params = null;
    private byte[] toSend = null; /* encrypted packet to send */
    private HandshakeStatus hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;

    /* Does TLS handshake need initialization */
    private boolean needInit = true;

    private boolean inBoundOpen = true;
    private boolean outBoundOpen = true;

    /* closed completely (post shutdown or before handshake) */
    private boolean closed = true;

    /* handshake started explicitly by user with beginHandshake() */
    private boolean handshakeStartedExplicitly = false;

    /* handshake completed */
    private boolean handshakeFinished = false;

    /* closeNotify status when shutting down */
    private boolean closeNotifySent = false;
    private boolean closeNotifyReceived = false;

    /* session stored (WOLFSSL_SESSION), relevant on client side */
    private boolean sessionStored = false;

    /* TLS 1.3 session ticket received (on client side) */
    private boolean sessionTicketReceived = false;

    /* client/server mode has been set */
    private boolean clientModeSet = false;

    private SendCB sendCb = null;
    private RecvCB recvCb = null;

    private ByteBuffer netData = null;
    private final Object netDataLock = new Object();

    /* Locks for synchronization */
    private final Object ioLock = new Object();
    private final Object toSendLock = new Object();

    /** ALPN selector callback, if set */
    protected BiFunction<SSLEngine, List<String>, String> alpnSelector = null;

    /** Turn on extra/verbose SSLEngine debug logging */
    public boolean extraDebugEnabled = false;

    /** Turn on Send/Recv callback debug to print out bytes sent/received.
     * WARNING: enabling this will slow down sending and receiving data,
     * enough so that app may run into timeouts. Enable with caution. */
    public boolean ioDebugEnabled = false;

    /**
     * Turns on additional debugging based on system properties set.
     */
    private void enableExtraDebug() {
        /* turn on verbose extra debugging if 'wolfsslengine.debug'
         * system property is set */
        String engineDebug  = System.getProperty("wolfsslengine.debug");
        if ((engineDebug != null) && (engineDebug.equalsIgnoreCase("true"))) {
            this.extraDebugEnabled = true;
        }
    }

    /**
     * Turns on additional debugging of I/O data based on system properties set.
     */
    private void enableIODebug() {
        /* turn on verbose extra debugging of bytes sent and received if
         * 'wolfsslengine.io.debug' system property is set */
        String engineIODebug = System.getProperty("wolfsslengine.io.debug");
        if ((engineIODebug != null) &&
            (engineIODebug.equalsIgnoreCase("true"))) {
            this.ioDebugEnabled = true;
        }
    }

    /**
     *  Create a new engine with no hints for session reuse
     *
     * @param ctx JNI level WolfSSLContext
     * @param auth WolfSSLAuthStore to use
     * @param params connection parameters to be used
     * @throws WolfSSLException if there is an issue creating the engine
     */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore auth, WolfSSLParameters params)
            throws WolfSSLException {
        super();
        this.ctx = ctx;
        this.authStore = auth;
        this.params = params.copy();
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE,
                             null, ex);
            throw new WolfSSLException("Error with init");
        }
        this.engineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
            this.params);

        try {
            this.engineHelper.LoadKeyAndCertChain(null, this);
        } catch (CertificateEncodingException | IOException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "failed to load private key and/or cert chain");
            throw new WolfSSLException(e);
        }
    }

    /**
     *  Create a new engine with hints for session reuse
     *
     * @param ctx JNI level WolfSSLContext
     * @param auth WolfSSLAuthStore to use
     * @param params connection parameters to be used
     * @param host to connect to
     * @param port to connect to
     * @throws WolfSSLException if there is an issue creating the engine
     */
    protected WolfSSLEngine(com.wolfssl.WolfSSLContext ctx,
            WolfSSLAuthStore auth, WolfSSLParameters params, String host,
            int port) throws WolfSSLException {
        super(host, port);
        this.ctx = ctx;
        this.authStore = auth;
        this.params = params.copy();
        try {
            initSSL();
        } catch (WolfSSLJNIException ex) {
            Logger.getLogger(WolfSSLEngine.class.getName()).log(Level.SEVERE,
                             null, ex);
            throw new WolfSSLException("Error with init");
        }
        this.engineHelper = new WolfSSLEngineHelper(this.ssl, this.authStore,
                this.params, port, host);

        try {
            this.engineHelper.LoadKeyAndCertChain(null, this);
        } catch (CertificateEncodingException | IOException e) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "failed to load private key and/or cert chain");
            throw new WolfSSLException(e);
        }
    }

    /**
     * Register I/O callbacks and contexts with WolfSSLSession and native
     * wolfSSL. Uses singleton pattern on callbacks.
     *
     * Call unsetSSLCallbacks to unset/unregister these. Since the I/O
     * context is set as the current SSLEngine object, this can prevent
     * garbage collection of this SSLEngine object unless the context
     * is unset from the WolfSSLSession.
     *
     * Protected by ioLock since all I/O operations are dependent on using
     * these underlying I/O callbacks.
     *
     * @throws WolfSSLJNIException on native JNI error
     */
    private void setSSLCallbacks() throws WolfSSLJNIException {

        synchronized (ioLock) {
            if (sendCb == null) {
                sendCb = new SendCB();
            }
            if (recvCb == null) {
                recvCb = new RecvCB();
            }
            ssl.setIORecv(recvCb);
            ssl.setIOSend(sendCb);
            ssl.setIOReadCtx(this);
            ssl.setIOWriteCtx(this);
        }
    }

    /**
     * Unregister I/O callbacks and contexts with WolfSSLSession and
     * native wolfSSL.
     *
     * Call setSSLCallbacks() to re-register these.
     *
     * Protected with ioLock since all I/O operations are dependent on
     * using these underlying I/O callbacks.
     *
     * @throws WolfSSLJNIException on native JNI error
     */
    private void unsetSSLCallbacks() throws WolfSSLJNIException {

        synchronized (ioLock) {
            ssl.setIORecv(null);
            ssl.setIOSend(null);
            ssl.setIOReadCtx(null);
            ssl.setIOWriteCtx(null);
        }
    }

    private void initSSL() throws WolfSSLException, WolfSSLJNIException {
        if (sendCb == null) {
            sendCb = new SendCB();
        }
        if (recvCb == null) {
            recvCb = new RecvCB();
        }

        /* will throw WolfSSLException if issue creating WOLFSSL */
        ssl = new WolfSSLSession(ctx);

        enableExtraDebug();
        enableIODebug();
    }

    /**
     * Copy buffered data to be sent into provided output ByteBuffer.
     *
     * Data sent will be minimum of either buffered data size or
     * destination buffer remaining space.
     *
     * Returns size of data copied.
     */
    private int CopyOutPacket(ByteBuffer out) {
        int sendSz = 0;

        synchronized (toSendLock) {
            if (this.toSend != null) {
                sendSz = Math.min(this.toSend.length, out.remaining());
                out.put(this.toSend, 0, sendSz);

                if (sendSz != this.toSend.length) {
                    /* resize and adjust remaining toSend data */
                    byte[] tmp = new byte[this.toSend.length - sendSz];
                    System.arraycopy(this.toSend, sendSz, tmp, 0,
                                     this.toSend.length - sendSz);
                    this.toSend = tmp;
                }
                else {
                    this.toSend = null;
                }
            }
        }
        return sendSz;
    }

    /**
     * Helper function, updates internal close_notify alert status
     * and inBound/outBoundOpen.
     */
    private synchronized void UpdateCloseNotifyStatus() {
        int ret;

        synchronized (ioLock) {
            ret = ssl.getShutdown();
        }
        if (ret == (WolfSSL.SSL_RECEIVED_SHUTDOWN |
                    WolfSSL.SSL_SENT_SHUTDOWN)) {
            this.closeNotifySent = true;
            this.closeNotifyReceived = true;
            this.inBoundOpen = false;
            if (this.toSend == null || this.toSend.length == 0) {
                /* Don't close outbound if we have a close_notify alert
                 * send back to peer. Native wolfSSL may have already generated
                 * it and is reflected in SSL_SENT_SHUTDOWN flag, but we
                 * might have it cached in our Java SSLEngine object still to
                 * be sent. */
                this.outBoundOpen = false;
            }
            closed = true;
        } else if (ret == WolfSSL.SSL_RECEIVED_SHUTDOWN) {
            this.closeNotifyReceived = true;
            this.inBoundOpen = false;
        } else if (ret == WolfSSL.SSL_SENT_SHUTDOWN) {
            this.closeNotifySent = true;
            this.outBoundOpen = false;
        }
    }

    /**
     * Handles logic during shutdown
     *
     * @return WolfSSL.SSL_SUCCESS on success, zero or negative on error
     * @throws SocketException if ssl.shutdownSSL() encounters a socket error
     * @throws SocketTimeoutException if ssl.shutdownSSL() times out
     */
    private synchronized int ClosingConnection()
        throws SocketException, SocketTimeoutException {

        int ret;

        /* Save session into WolfSSLAuthStore cache, saves session
         * pointer for resumption if on client side. Protected with ioLock
         * since underlying get1Session can use I/O with peek.
         *
         * Only store session if handshake is finished, SSL_get_error() does
         * not have an active error state, and the session has not been
         * stored previously. */
        synchronized (ioLock) {
            if (this.handshakeFinished && (ssl.getError(0) == 0) &&
                !this.sessionStored) {
                this.engineHelper.saveSession();
            }
        }

        /* get current close_notify state */
        UpdateCloseNotifyStatus();
        if (this.closeNotifySent && this.closeNotifyReceived) {
            return WolfSSL.SSL_SUCCESS;
        }

        /* send/recv close_notify as needed */
        synchronized (ioLock) {
            ret = ssl.shutdownSSL();
            if (ssl.getError(ret) == WolfSSL.SSL_ERROR_ZERO_RETURN) {
                /* got close_notify alert, reset ret to SSL_SUCCESS to continue
                 * and let corresponding close_notify to be sent */
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ClosingConnection(), ssl.getError() is ZERO_RETURN");
                ret = WolfSSL.SSL_SUCCESS;
            }
        }
        UpdateCloseNotifyStatus();

        return ret;
    }

    /**
     * Starts or continues SSL/TLS handshake.
     *
     * @return WolfSSL.SSL_SUCCESS or WolfSSL.SSL_FAILURE
     * @throws SocketException if ssl.connect() or ssl.accept() encounters
     *         a socket exception.
     * @throws SocketTimeoutException if ssl.connect() or ssl.accept()
     *         times out. This should not happen since infinite timeout is
     *         being used for these calls.
     */
    private synchronized int DoHandshake() throws SSLException {
        int ret = WolfSSL.SSL_SUCCESS;

        try {
            if (this.getUseClientMode()) {
                synchronized (ioLock) {
                    ret = this.ssl.connect();

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.connect() ret:err = " + ret + " : " +
                        ssl.getError(ret));
                }
            }
            else {
                synchronized (ioLock) {
                    ret = this.ssl.accept();

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ssl.accept() ret:err = " + ret + " : " +
                        ssl.getError(ret));
                }
            }

        } catch (SocketTimeoutException | SocketException e) {
            throw new SSLException(e);
        }

        return ret;
    }

    /**
     * Write application data using ssl.write().
     *
     * Only sends up to maximum app data chunk size
     * (SSLSession.getApplicationBufferSize()).
     *
     * @throws SocketException if ssl.write() encounters a socket error
     * @throws SocketTimeoutException if ssl.write() times out. Shouldn't
     *         happen since this is using an infinite timeout.
     * @return bytes sent on success, negative on error
     */
    private synchronized int SendAppData(ByteBuffer[] in, int ofst, int len)
        throws SocketException, SocketTimeoutException {

        int i = 0;
        int ret = 0;
        int totalIn = 0;
        int sendSz = 0;
        int inputLeft = 0;
        ByteBuffer dataBuf;
        byte[] dataArr;
        int[] pos = new int[len];   /* in[] positions */
        int[] limit = new int[len]; /* in[] limits */

        /* get total input data size, store input array positions */
        for (i = ofst; i < ofst + len; i++) {
            totalIn += in[i].remaining();
            pos[i] = in[i].position();
            limit[i] = in[i].limit();
        }

        /* only send up to maximum app data size chunk */
        sendSz = Math.min(totalIn,
            this.engineHelper.getSession().getApplicationBufferSize());
        dataBuf = ByteBuffer.allocate(sendSz);

        /* gather byte array of sendSz bytes from input buffers */
        inputLeft = sendSz;
        for (i = ofst; i < ofst + len; i++) {
            int bufChunk = Math.min(in[i].remaining(), inputLeft);

            in[i].limit(in[i].position() + bufChunk);       /* set limit */
            dataBuf.put(in[i]);                             /* get data */
            inputLeft -= bufChunk;
            in[i].limit(limit[i]);                          /* reset limit */

            if (inputLeft == 0) {
                break; /* reached data size needed, stop reading */
            }
        }

        dataArr = new byte[sendSz];
        dataBuf.rewind();
        dataBuf.get(dataArr);

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                         "calling ssl.write() with size: " + sendSz);

        synchronized (ioLock) {
            ret = this.ssl.write(dataArr, sendSz);
        }
        if (ret <= 0) {
            /* error, reset in[] positions for next call */
            for (i = ofst; i < ofst + len; i++) {
                in[i].position(pos[i]);
            }
        }

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                         "ssl.write() returning: " + ret);

        return ret;
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        if (in == null) {
            throw new SSLException("SSLEngine.wrap() bad arguments");
        }

        return wrap(new ByteBuffer[] { in }, 0, 1, out);
    }

    @Override
    public synchronized SSLEngineResult wrap(ByteBuffer[] in, int ofst, int len,
            ByteBuffer out) throws SSLException {
        int ret = 0, i;
        int produced = 0;
        int consumed = 0;

        /* Set initial status for SSLEngineResult return */
        Status status = SSLEngineResult.Status.OK;

        /* Sanity check buffer arguments. */
        if (in == null || ofst + len > in.length || out == null) {
            throw new SSLException("SSLEngine.wrap() bad arguments");
        }

        if (ofst < 0 || len < 0) {
            throw new IndexOutOfBoundsException();
        }

        for (i = ofst; i < len; ++i) {
            if (in[i] == null) {
                throw new SSLException("SSLEngine.wrap() bad arguments");
            }
        }

        if (out.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }

        if (!this.clientModeSet) {
            throw new IllegalStateException(
                    "setUseClientMode() has not been called on this SSLEngine");
        }

        if (extraDebugEnabled) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ entering wrap() ] ===================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + this.engineHelper.getUseClientMode());
            for (i = 0; i < len; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].remaining(): " + in[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].position(): " + in[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].limit(): " + in[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", len: " + len);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.remaining(): " + out.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.position(): " + out.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.limit(): " + out.limit());
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.inBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        /* Set wolfSSL I/O callbacks and context for read/write operations */
        try {
            setSSLCallbacks();
        } catch (WolfSSLJNIException e) {
            throw new SSLException(e);
        }

        if (needInit) {
            this.engineHelper.initHandshake(this);
            needInit = false;
            closed = false; /* opened a connection */
        }

        synchronized (netDataLock) {
            this.netData = null;
        }

        /* Force out buffer to be large enough to hold max packet size */
        if (out.remaining() <
            this.engineHelper.getSession().getPacketBufferSize()) {
            return new SSLEngineResult(Status.BUFFER_OVERFLOW, hs, 0, 0);
        }

        /* Copy buffered data to be sent into output buffer */
        produced = CopyOutPacket(out);

        /* Closing down connection if buffered data has been sent and:
         * 1. Outbound has been closed (!outBoundOpen)
         * 2. Inbound is closed and close_notify has been sent
         */
        if (produced >= 0 &&
            (!outBoundOpen || (!inBoundOpen && this.closeNotifySent))) {
            /* Mark SSLEngine status as CLOSED */
            status = SSLEngineResult.Status.CLOSED;
            /* Handshake has finished and SSLEngine is closed, release
             * global JNI verify callback pointer */
            this.engineHelper.unsetVerifyCallback();

            try {
                ClosingConnection();
            } catch (SocketException | SocketTimeoutException e) {
                throw new SSLException(e);
            }
            produced += CopyOutPacket(out);
        }
        else if ((produced > 0) && !inBoundOpen &&
                 (!this.closeNotifySent && !this.closeNotifyReceived)) {
            /* We had buffered data to send, but inbound was already closed.
             * Most likely this is because we needed to send an alert to
             * the peer. We should now mark outbound as closed since we
             * won't be sending anything after the alert went out. */
            this.outBoundOpen = false;
        }
        else if (produced == 0) {
            /* continue handshake or application data */
            if (!this.handshakeFinished) {
                ret = DoHandshake();
            }
            else {
                try {
                    ret = SendAppData(in, ofst, len);
                    if (ret > 0) {
                        consumed += ret;
                    }
                } catch (SocketException | SocketTimeoutException e) {
                    throw new SSLException(e);
                }
            }

            /* copy any produced data into output buffer */
            produced += CopyOutPacket(out);
        }

        SetHandshakeStatus(ret);

        if (extraDebugEnabled) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ exiting wrap() ] ===================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + this.engineHelper.getUseClientMode());
            for (i = 0; i < len; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].remaining(): " + in[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].position(): " + in[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ByteBuffer in["+i+"].limit(): " + in[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", len: " + len);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.remaining(): " + out.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.position(): " + out.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "out.limit(): " + out.limit());
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.inBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "consumed: " + consumed);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "produced: " + produced);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        try {
            /* Don't hold references to this SSLEngine object in WolfSSLSession,
             * can prevent proper garbage collection */
            unsetSSLCallbacks();

        } catch (WolfSSLJNIException e) {
            throw new SSLException(e);
        }

        return new SSLEngineResult(status, hs, consumed, produced);
    }

    /**
     * Return total remaining space in array of ByteBuffers.
     *
     * @param out array of ByteBuffers to be polled for available space
     * @param ofst offset into out array to begin
     * @param length length of ByteBuffer array
     *
     * @return number of available/remaining bytes in array of ByteBuffers
     * @throws IllegalArgumentException if readonly buffer found
     */
    private static synchronized int getTotalOutputSize(ByteBuffer[] out,
                                          int ofst, int length) {
        int i = 0;
        int maxOutSz = 0;

        for (i = 0; i < length; i++) {
            if (out[i + ofst] == null || out[i + ofst].isReadOnly()) {
                throw new IllegalArgumentException(
                    "null or readonly out buffer found");
            }
            maxOutSz += out[i + ofst].remaining();
        }

        return maxOutSz;
    }

    /**
     * Receive application data using ssl.read() from in buffer, placing
     * processed/decrypted data into out[].
     *
     * @param out output ByteBuffer arrays, to hold processed/decoded plaintext
     * @param ofst offset into out[] array to begin writing data
     * @param length length of out[] array
     *
     * @throws SSLException if ssl.read() encounters socket error
     * @return number of plaintext bytes received, or negative on error.
     */
    private synchronized int RecvAppData(ByteBuffer[] out, int ofst, int length)
        throws SSLException {

        int i, sz, bufSpace;
        int totalRead = 0;
        int maxOutSz = 0;
        int ret = 0;
        int idx = 0; /* index into out[] array */
        int err = 0;
        byte[] tmp;

        /* create read buffer of max output size */
        maxOutSz = getTotalOutputSize(out, ofst, length);
        tmp = new byte[maxOutSz];

        synchronized (ioLock) {
            try {
                ret = this.ssl.read(tmp, maxOutSz);
            } catch (SocketTimeoutException | SocketException e) {
                throw new SSLException(e);
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "RecvAppData(), ssl.read() ret = " + ret);

            err = ssl.getError(ret);
        }

        if (ret <= 0) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "RecvAppData(), ssl.getError() = " + err);

            switch (err) {
                case WolfSSL.SSL_ERROR_WANT_READ:
                case WolfSSL.SSL_ERROR_WANT_WRITE:
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "RecvAppData(), got WANT_READ/WANT_WRITE");
                    break;

                /* In 0 and ZERO_RETURN cases we may have gotten a
                 * close_notify alert, check on shutdown status */
                case WolfSSL.SSL_ERROR_ZERO_RETURN:
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "RecvAppData(), got ZERO_RETURN");
                    /* Fall through on purpose */
                case 0:
                    /* check if is shutdown message */
                    synchronized (ioLock) {
                        if (ssl.getShutdown() ==
                                WolfSSL.SSL_RECEIVED_SHUTDOWN) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "RecvAppData(), received shutdown message");
                            try {
                                ret = ClosingConnection();
                                if (ret > 0) {
                                    /* Returns number of bytes read,
                                     * 0, or err */
                                    ret = 0;
                                }
                            } catch (SocketException |
                                     SocketTimeoutException e) {
                                throw new SSLException(e);
                            }
                            return ret;
                        }
                    }
                    break;
                default:
                    throw new SSLException("wolfSSL_read() error: " +
                            ret + " , err = " + err);
            }
        }
        else {
            /* write processed data into output buffers */
            for (i = 0; i < ret;) {
                if (idx + ofst >= length) {
                    /* no more output buffers left */
                    break;
                }

                bufSpace = out[idx + ofst].remaining();
                if (bufSpace == 0) {
                    /* no more space in current out buffer, advance */
                    idx++;
                    continue;
                }

                sz = (bufSpace >= (ret - i)) ? (ret - i) : bufSpace;
                out[idx + ofst].put(tmp, i, sz);
                i += sz;
                totalRead += sz;

                if ((ret - i) > 0) {
                    idx++; /* go to next output buffer */
                }
            }
        }

        return totalRead;
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer in, ByteBuffer out)
            throws SSLException {
        if (out == null) {
            throw new IllegalArgumentException(
                "SSLEngine.unwrap() bad arguments");
        }

        return unwrap(in, new ByteBuffer[] { out }, 0, 1);
    }

    @Override
    public synchronized SSLEngineResult unwrap(ByteBuffer in, ByteBuffer[] out,
            int ofst, int length) throws SSLException {
        int i, ret = 0, sz = 0, err = 0;
        int inPosition = 0;
        int inRemaining = 0;
        int consumed = 0;
        int produced = 0;
        byte[] tmp;

        /* Set initial status for SSLEngineResult return */
        Status status = SSLEngineResult.Status.OK;

        /* Sanity check buffer arguments. */
        if (in == null || out == null || ofst + length > out.length) {
            throw new IllegalArgumentException(
                "SSLEngine.unwrap() bad arguments");
        }

        if (ofst < 0 || length < 0) {
            throw new IndexOutOfBoundsException();
        }

        for (i = ofst; i < length; ++i) {
            if (out[i] == null) {
                throw new IllegalArgumentException("SSLEngine.unwrap() bad arguments");
            }

            if (out[i].isReadOnly()) {
                throw new ReadOnlyBufferException();
            }
        }

        if (!this.clientModeSet) {
            throw new IllegalStateException(
                "setUseClientMode() has not been called on this SSLEngine");
        }

        synchronized (netDataLock) {
            this.netData = in;
            inPosition = in.position();
            inRemaining = in.remaining();
        }

        if (extraDebugEnabled) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ entering unwrap() ] =================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + this.engineHelper.getUseClientMode());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.remaining(): " + in.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.position(): " + in.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.limit(): " + in.limit());
            for (i = 0; i < length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].remaining(): " + out[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].position(): " + out[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].limit(): " + out[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", length: " + length);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.inBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        /* Set wolfSSL I/O callbacks and context for read/write operations */
        try {
            setSSLCallbacks();
        } catch (WolfSSLJNIException e) {
            throw new SSLException(e);
        }

        if (getUseClientMode() && needInit) {
            /* If unwrap() is called before handshake has started, return
             * WANT_WRAP since we'll need to send a ClientHello first */
            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        else if (hs == SSLEngineResult.HandshakeStatus.NEED_WRAP &&
                 (this.toSend != null) && (this.toSend.length > 0)) {
            /* Already have data buffered to send and in NEED_WRAP state,
             * just return so wrap() can be called */
            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
        }
        else {

            if (needInit) {
                this.engineHelper.initHandshake(this);
                needInit = false;
                closed = false;
            }

            if (outBoundOpen == false) {
                try {
                    if (ClosingConnection() == WolfSSL.SSL_SUCCESS) {
                        /* Mark SSLEngine status as CLOSED */
                        status = SSLEngineResult.Status.CLOSED;
                        /* Handshake has finished and SSLEngine is closed,
                         * release, global JNI verify callback pointer */
                        this.engineHelper.unsetVerifyCallback();
                    }
                } catch (SocketException | SocketTimeoutException e) {
                    throw new SSLException(e);
                }
            }
            else {

                if (this.handshakeFinished == false) {

                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "starting or continuing handshake");
                    ret = DoHandshake();
                }
                else {
                    /* If we have input data, make sure output buffer length is
                     * greater than zero, otherwise ask app to expand out buffer.
                     * There may be edge cases where this could be tightened up,
                     * but this will err on the side of giving us more output
                     * space than we need. */
                    if (inRemaining > 0 &&
                        getTotalOutputSize(out, ofst, length) == 0) {
                        status = SSLEngineResult.Status.BUFFER_OVERFLOW;
                    }
                    else {
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "receiving application data");
                        ret = RecvAppData(out, ofst, length);
                        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                            "received application data: " + ret +
                            " bytes (from RecvAppData)");
                        if (ret > 0) {
                            produced += ret;
                        }
                        else {
                            synchronized (netDataLock) {
                                if (ret == 0 && in.remaining() > 0 &&
                                    getTotalOutputSize(out, ofst,
                                        length) == 0) {
                                    /* We have more data to read, but no more
                                     * out space left in ByteBuffer[], ask for
                                     * more */
                                    status =
                                        SSLEngineResult.Status.BUFFER_OVERFLOW;
                                }
                            }
                        }
                    }

                    /* If we haven't stored session yet, try again. For TLS 1.3
                     * we may need to wait for session ticket. We do try
                     * right after wolfSSL_connect/accept() finishes, but
                     * we might not have had session ticket at that time. */
                    synchronized (ioLock) {
                        if (this.handshakeFinished && (ssl.getError(0) == 0) &&
                            !this.sessionStored) {
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "calling engineHelper.saveSession()");
                            int ret2 = this.engineHelper.saveSession();
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "return from saveSession(), ret = " + ret2);
                            if (ret2 == WolfSSL.SSL_SUCCESS) {
                                this.sessionStored = true;
                            }
                        }
                    }
                }

                if (outBoundOpen == false || this.closeNotifySent) {
                    /* Mark SSLEngine status as CLOSED */
                    status = SSLEngineResult.Status.CLOSED;
                    /* Handshake has finished and SSLEngine is closed,
                     * release, global JNI verify callback pointer */
                    this.engineHelper.unsetVerifyCallback();
                }

                synchronized (ioLock) {
                    err = ssl.getError(ret);
                }
                if (ret < 0 &&
                    (err != WolfSSL.SSL_ERROR_WANT_READ) &&
                    (err != WolfSSL.SSL_ERROR_WANT_WRITE)) {
                    if (err == WolfSSL.UNKNOWN_ALPN_PROTOCOL_NAME_E) {
                        /* Native wolfSSL could not negotiate a common ALPN
                         * protocol */
                        this.inBoundOpen = false;
                        throw new SSLHandshakeException(
                            "Unrecognized protocol name error, ret:err = " +
                            ret + " : " + err);
                    }
                    else {
                        /* Native wolfSSL threw an exception when unwrapping
                         * data, close inbound since we can't receive more
                         * data */
                        this.inBoundOpen = false;
                        if (err == WolfSSL.FATAL_ERROR) {
                            /* If client side and we received fatal alert,
                             * close outbound since we won't be receiving
                             * any more data */
                            this.outBoundOpen = false;
                        }
                        throw new SSLException(
                            "wolfSSL error, ret:err = " + ret + " : " + err);
                    }
                }

                synchronized (toSendLock) {
                    synchronized (netDataLock) {
                        if (ret < 0 && err == WolfSSL.SSL_ERROR_WANT_READ &&
                            in.remaining() == 0 && (this.toSend == null ||
                            (this.toSend != null && this.toSend.length == 0))) {
                            /* Need more data */
                            status = SSLEngineResult.Status.BUFFER_UNDERFLOW;
                        }
                    }
                }
            }

            synchronized (netDataLock) {
                consumed += in.position() - inPosition;
            }
            SetHandshakeStatus(ret);
        }

        /* If client side, handshake is done, and we have just received a
         * TLS 1.3 session ticket, we should return FINISHED HandshakeStatus
         * from unwrap() directly but not from getHandshakeStatus(). Keep track
         * of if we have received ticket, so we only set/return this once */
        synchronized (ioLock) {
            if (this.getUseClientMode() && this.handshakeFinished &&
                this.ssl.hasSessionTicket() &&
                this.sessionTicketReceived == false) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "received session ticket, returning " +
                    "HandshakeStatus FINISHED");
                hs = SSLEngineResult.HandshakeStatus.FINISHED;
                this.sessionTicketReceived = true;
            }
        }

        if (extraDebugEnabled == true) {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "==== [ exiting unwrap() ] ==================================");
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "setUseClientMode: " + this.engineHelper.getUseClientMode());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.remaining(): " + in.remaining());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.position(): " + in.position());
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "in.limit(): " + in.limit());
            for (i = 0; i < length; i++) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].remaining(): " + out[i].remaining());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].position(): " + out[i].position());
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "out["+i+"].limit(): " + out[i].limit());
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ofst: " + ofst + ", length: " + length);
            if (this.toSend != null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: " + this.toSend.length);
            } else {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "toSend.length: 0");
            }
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeFinished: " + this.handshakeFinished);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifySent: " + this.closeNotifySent);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "closeNotifyReceived: " + this.closeNotifyReceived);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "inBoundOpen: " + this.inBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "outBoundOpen: " + this.outBoundOpen);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "handshakeStatus: " + hs);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "status: " + status);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "consumed: " + consumed);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "produced: " + produced);
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "===========================================================");
        }

        try {
            /* Don't hold references to this SSLEngine object in WolfSSLSession,
             * can prevent proper garbage collection */
            unsetSSLCallbacks();

        } catch (WolfSSLJNIException e) {
            throw new SSLException(e);
        }

        return new SSLEngineResult(status, hs, consumed, produced);
    }

    /**
     * Sets handshake status after I/O operation of unwrap(), helper function.
     */
    private synchronized void SetHandshakeStatus(int ret) {

        int err = 0;

        /* Get current wolfSSL error, synchronize on ioLock in case I/O is
         * happening and error state may change */
        synchronized (ioLock) {
            err = ssl.getError(ret);
        }

        /* Lock access to this.toSend and this.toRead */
        synchronized (toSendLock) {
            if (this.handshakeFinished == true) {
                /* close_notify sent by wolfSSL but not across transport yet */
                if (this.closeNotifySent == true &&
                    this.toSend != null && this.toSend.length > 0) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                /* close_notify received, need to send one back */
                else if (this.closeNotifyReceived == true &&
                         this.closeNotifySent == false) {
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                /* close_notify sent, need to read peer's */
                else if (this.closeNotifySent == true &&
                         this.closeNotifyReceived == false) {
                    /* Receiving close_notify is optional after we have sent
                     * one. Denote that with NOT_HANDSHAKING here */
                    hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                }
                else if (!this.outBoundOpen && !this.closeNotifySent) {
                    /* We just closed outBound, NEED_WRAP to generate and
                     * send close_notify */
                    hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                }
                else {
                    hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                }
            }
            else {
                synchronized (netDataLock) {
                    synchronized (ioLock) {
                        if (ssl.handshakeDone() && this.toSend == null) {
                            this.handshakeFinished = true;
                            hs = SSLEngineResult.HandshakeStatus.FINISHED;

                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "SSL/TLS handshake finished");
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "SSL/TLS protocol: " +
                                this.engineHelper.getSession().getProtocol());
                            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                                "SSL/TLS cipher suite: " +
                                this.engineHelper.getSession().getCipherSuite());
                        }
                        /* give priority of WRAP/UNWRAP to state of our internal
                         * I/O data buffers first, then wolfSSL err status */
                        else if (this.toSend != null && this.toSend.length > 0) {
                            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                        }
                        else if (this.netData != null &&
                                 this.netData.remaining() > 0 &&
                                 this.inBoundOpen == true) {
                            hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                        }
                        else if (err == WolfSSL.SSL_ERROR_WANT_READ) {
                            hs = SSLEngineResult.HandshakeStatus.NEED_UNWRAP;
                        }
                        else if (err == WolfSSL.SSL_ERROR_WANT_WRITE) {
                            hs = SSLEngineResult.HandshakeStatus.NEED_WRAP;
                        }
                        else {
                            hs = SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING;
                        }
                    } /* synchronized ioLock */
                } /* synchronized netDataLock */
            }
        } /* synchronized toSendLock */

        return;
    }

    @Override
    public Runnable getDelegatedTask() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getDelegatedTask()");
        /* no tasks left to run */
        return null;
    }

    @Override
    public synchronized void closeInbound() throws SSLException {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered closeInbound");

        if (!inBoundOpen)
            return;

        if (inBoundOpen && !closed) {
            /* this checks that peer sent back shutdown message */
            throw new SSLException("Closing in bound before shutdown is done");
        }
        else
        {
            inBoundOpen = false;
        }
    }

    @Override
    public synchronized boolean isInboundDone() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered isInboundDone()");
        return !inBoundOpen;
    }

    @Override
    public synchronized void closeOutbound() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered closeOutbound, outBoundOpen = false");
        outBoundOpen = false;

        /* If handshake has not started yet, close inBound as well */
        if (needInit) {
            inBoundOpen = true;
        }

        /* Update status based on internal state. Some calling applications
         * loop around getHandshakeStatus(), it needs to be up to date. */
        SetHandshakeStatus(0);
    }

    @Override
    public synchronized boolean isOutboundDone() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered isOutboundDone()");
        return !outBoundOpen;
    }

    @Override
    public String[] getSupportedCipherSuites() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedCipherSuites()");
        return this.engineHelper.getAllCiphers();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledCipherSuites()");
        return this.engineHelper.getCiphers();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledCipherSuites()");
        this.engineHelper.setCiphers(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSupportedProtocols()");
        return this.engineHelper.getAllProtocols();
    }

    @Override
    public synchronized String[] getEnabledProtocols() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnabledProtocols()");
        return this.engineHelper.getProtocols();
    }

    @Override
    public synchronized void setEnabledProtocols(String[] protocols) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnabledProtocols()");
        this.engineHelper.setProtocols(protocols);
    }

    @Override
    public synchronized SSLSession getSession() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSession()");
        return this.engineHelper.getSession();
    }

    /**
     * Has the underlying WOLFSSL / WolfSSLSession been resumed / reused.
     * This calls down to native wolfSSL_session_reused()
     *
     * NON-STANDARD API, not part of JSSE. Must cast SSLEngine back
     * to WolfSSLEngine to use.
     *
     * @return true if session has been resumed, otherwise false
     * @throws SSLException if native JNI call fails or underlying
     *         WolfSSLSession has been freed
     */
    public synchronized boolean sessionResumed() throws SSLException {
        if (this.ssl != null) {
            try {
                int resume = this.ssl.sessionReused();
                if (resume == 1) {
                    return true;
                }
            } catch (IllegalStateException | WolfSSLJNIException e) {
                throw new SSLException(e);
            }
        }

        return false;
    }

    public synchronized SSLSession getHandshakeSession() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeSession()");
        return this.engineHelper.getSession();
    }

    /**
     * Explicitly start the SSL/TLS handshake.
     *
     * This method does not block until handshake is completed, unlike
     * the SSLSocket.startHandshake() method.
     *
     * The handshake may be started implicitly by a call to wrap() or unwrap(),
     * if those methods are called and the handshake is not done yet. In that
     * case, the user has not explicitly started the handshake themselves
     * and may inadvertently call beginHandshake() unknowing that the handshake
     * has already started. For that case, we should just return without
     * error/exception, since the user is just trying to start the first
     * initial handshake.
     *
     * beginHandshake() may also be called again to initiate renegotiation.
     * wolfJSSE does not support renegotiation inside SSLEngine yet. In that
     * case, we throw an SSLException to notify callers renegotiation is not
     * supported.
     *
     * @throws SSLException if a problem was encountered while initiating
     *         a SSL/TLS handshake on this SSLEngine.
     * @throws IllegalStateException if the client/server mode has not yet
     *         been set.
     */
    @Override
    public synchronized void beginHandshake() throws SSLException {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered beginHandshake()");

        if (!this.clientModeSet) {
            throw new IllegalStateException(
                "setUseClientMode() has not been called on this SSLEngine");
        }

        if (this.handshakeStartedExplicitly) {
            /* Renegotiation (thus calling beginHandshake() multiple times)
             * is not supported in wolfJSSE SSLEngine implementation yet. If
             * already called once by user, throw SSLException. */
            throw new SSLException("Renegotiation not supported");
        }
        else if (!this.needInit && !this.handshakeFinished) {
            /* Handshake has started implicitly by wrap() or unwrap(). Simply
             * return since this is the first time that the user has called
             * beginHandshake() themselves. */
            this.handshakeStartedExplicitly = true;
            return;
        }

        /* No network data source yet */
        synchronized (netDataLock) {
            this.netData = null;
        }

        if (outBoundOpen == false) {
            throw new SSLException(
                "beginHandshake() called but outbound closed");
        }

        try {
            setSSLCallbacks();
        } catch (WolfSSLJNIException e) {
            throw new SSLException(e);
        }

        if (needInit == true) {
            /* will throw SSLHandshakeException if session creation is
               not allowed */
            this.engineHelper.initHandshake(this);
            needInit = false;
        }

        try {
            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "calling engineHelper.doHandshake()");
            int ret = this.engineHelper.doHandshake(1, 0);
            SetHandshakeStatus(ret);

            /* Mark that the user has explicitly started the handshake
             * on this SSLEngine by calling beginHandshake() */
            this.handshakeStartedExplicitly = true;

        } catch (SocketTimeoutException e) {
            e.printStackTrace();
            throw new SSLException(e);

        } finally {

            try {
                /* Don't hold references to this SSLEngine object in
                 * WolfSSLSession, can prevent proper garbage collection */
                unsetSSLCallbacks();

            } catch (WolfSSLJNIException e) {
                throw new SSLException(e);
            }
        }
    }

    @Override
    public synchronized SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeStatus(): " + hs);

        /* Update status based on internal state. Some calling applications
         * loop around getHandshakeStatus(), it needs to be up to date. */
        SetHandshakeStatus(0);

        return hs;
    }

    @Override
    public synchronized void setUseClientMode(boolean mode) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setUseClientMode(" + mode + ")");
        this.engineHelper.setUseClientMode(mode);
        this.clientModeSet = true;
    }

    @Override
    public synchronized boolean getUseClientMode() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getUseClientMode()");
        return this.engineHelper.getUseClientMode();
    }

    @Override
    public synchronized void setNeedClientAuth(boolean need) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setNeedClientAuth(" + need + ")");
        this.engineHelper.setNeedClientAuth(need);
    }

    @Override
    public synchronized boolean getNeedClientAuth() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getNeedClientAuth()");
        return this.engineHelper.getNeedClientAuth();
    }

    @Override
    public synchronized void setWantClientAuth(boolean want) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setWantClientAuth(" + want + ")");
        this.engineHelper.setWantClientAuth(want);
    }

    @Override
    public synchronized boolean getWantClientAuth() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getWantClientAuth()");
        return this.engineHelper.getWantClientAuth();
    }

    @Override
    public synchronized void setEnableSessionCreation(boolean flag) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setEnableSessionCreation(" + flag + ")");
        this.engineHelper.setEnableSessionCreation(flag);
    }

    @Override
    public synchronized boolean getEnableSessionCreation() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getEnableSessionCreation()");
        return this.engineHelper.getEnableSessionCreation();
    }

    public synchronized String getApplicationProtocol() {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getApplicationProtocol()");
        return this.engineHelper.getAlpnSelectedProtocolString();
    }

    /**
     * Returns the application protocol value negotiated on a handshake
     * currently in progress.
     *
     * After the handshake has finished, this will return null. To get the
     * ALPN protocol negotiated during the handshake, after it has completed,
     * call getApplicationProtocol().
     *
     * Not marked at @Override since this API was added as of
     * Java SE 8 Maintenance Release 3, and Java 7 SSLSocket will not
     * have this.
     *
     * @return String representating the application protocol negotiated
     */
    public synchronized String getHandshakeApplicationProtocol() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeApplicationProtocol()");

        if (!this.needInit && !this.handshakeFinished) {
            return this.engineHelper.getAlpnSelectedProtocolString();
        }

        return null;
    }

    /**
     * Returns the callback that selects an application protocol during the
     * SSL/TLS handshake.
     *
     * @return the callback function, or null if no callback has been set
     */
    public synchronized BiFunction<SSLEngine,List<String>,String>
        getHandshakeApplicationProtocolSelector() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getHandshakeApplicationProtocolSelector()");

        return this.alpnSelector;
    }

    /**
     * Registers a callback function that selects an application protocol
     * value for the SSL/TLS handshake.
     *
     * Usage of this callback will override any values set by
     * SSLParameters.setApplicationProtocols().
     *
     * Callback argument descriptions:
     *
     *    SSLEngine - the current SSLEngine, allows for inspection by the
     *                callback if needed
     *    List&lt;String&gt; - List of Strings representing application protocol
     *                   names sent by the peer
     *    String - Result of the callback is an application protocol
     *             name String, or null if none of the peer's protocols
     *             are acceptable. If return value is an empty String,
     *             ALPN will not be used.
     *
     * @param selector callback used to select ALPN protocol for handshake
     */
    public synchronized void setHandshakeApplicationProtocolSelector(
        BiFunction<SSLEngine,List<String>,String> selector) {

        int ret = 0;

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setHandshakeApplicationProtocolSelector()");

        if (selector != null) {
            ALPNSelectCallback alpnCb = new ALPNSelectCallback();

            try {
                /* Pass in SSLSocket Object for use inside callback */
                ret = this.ssl.setAlpnSelectCb(alpnCb, this);
                if (ret != WolfSSL.SSL_SUCCESS) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "Native setAlpnSelectCb() failed, ret = " + ret +
                        ", not setting selector");
                    return;
                }

                /* called from within ALPNSelectCallback during the handshake */
                this.alpnSelector = selector;

            } catch (WolfSSLJNIException e) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "Exception while calling ssl.setAlpnSelectCb, not setting");
            }
        }
    }

    /**
     * Inner class that implement the ALPN select callback which is registered
     * with our com.wolfssl.WolfSSLSession when
     * setHandshakeApplicationProtocolSelector() has been called.
     */
    class ALPNSelectCallback implements WolfSSLALPNSelectCallback
    {
        public int alpnSelectCallback(WolfSSLSession ssl, String[] out,
            String[] in, Object arg) {

            SSLEngine engine = (SSLEngine)arg;
            List<String> peerProtos = new ArrayList<String>();
            String selected = null;

            if (alpnSelector == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "alpnSelector null inside ALPNSelectCallback");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            if (!(arg instanceof SSLEngine)) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "alpnSelectCallback arg not type of SSLEngine");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            if (in.length == 0) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "peer protocol list is 0 inside alpnSelectCallback");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }

            WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                "ALPN protos sent by peer: " + Arrays.toString(in));

            for (String s: in) {
                peerProtos.add(s);
            }
            selected = alpnSelector.apply(engine, peerProtos);

            if (selected == null) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ALPN protocol string is null, no peer match");
                return WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            else {
                if (selected.isEmpty()) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "ALPN not being used, selected proto empty");
                    return WolfSSL.SSL_TLSEXT_ERR_NOACK;
                }

                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "ALPN protocol selected by callback: " + selected);
                out[0] = selected;
                return WolfSSL.SSL_TLSEXT_ERR_OK;

            }
        }
    }


    /**
     * Set the SSLParameters for this SSLEngine.
     *
     * @param params SSLParameters to set for this SSLEngine object
     */
    public synchronized void setSSLParameters(SSLParameters params) {
        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered setSSLParameters()");
        if (params != null) {
            WolfSSLParametersHelper.importParams(params, this.params);
        }
    }

    /**
     * Gets the SSLParameters for this SSLEngine.
     *
     * @return SSLParameters for this SSLEngine object.
     */
    @Override
    public synchronized SSLParameters getSSLParameters() {

        WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
            "entered getSSLParameters()");

        return WolfSSLParametersHelper.decoupleParams(this.params);
    }

    /**
     * Copies buffer to end of to send queue. Encrypted packet is ready to be
     * sent out.
     *
     * @param in byte array with encrypted data to be sent
     * @param sz size of data in input array to be sent
     *
     * @return number of bytes placed into send queue
     */
    protected synchronized int internalSendCb(byte[] in, int sz) {
        int totalSz = sz, idx = 0;
        byte[] prevToSend = null;

        synchronized (toSendLock) {
            /* Make copy of existing toSend array before expanding */
            if (this.toSend != null) {
                prevToSend = this.toSend.clone();
                totalSz += this.toSend.length;
            }

            /* Allocate new array to hold data to be sent */
            this.toSend = new byte[totalSz];

            /* Copy existing toSend data over */
            if (prevToSend != null) {
                System.arraycopy(prevToSend, 0, this.toSend, idx,
                                 prevToSend.length);
                idx += prevToSend.length;
            }
            System.arraycopy(in, 0, this.toSend, idx, sz);
        }

        if (ioDebugEnabled == true) {
            WolfSSLDebug.logHex(getClass(), WolfSSLDebug.INFO,
                                "CB Write", in, sz);
        }

        return sz;
    }

    /**
     * Internal receive callback. Reads from netData and gives bytes back
     * to native wolfSSL for processing.
     *
     * @param toRead byte array into which to place data read from transport
     * @param sz number of bytes that should be read/copied from transport
     *
     * @return number of bytes read into toRead array or negative
     *         value on error
     */
    protected synchronized int internalRecvCb(byte[] toRead, int sz) {

        int max = 0;

        synchronized (netDataLock) {
            if (ioDebugEnabled == true) {
                WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                    "CB Read: requesting " + sz + " bytes");
                if (this.netData != null) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "CB Read: netData.remaining() = " +
                        this.netData.remaining());
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "CB Read: netData.position() = " +
                        this.netData.position());
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "CB Read: netData.limit() = " +
                        this.netData.limit());
                }
            }

            if (this.netData == null || this.netData.remaining() == 0) {
                if (ioDebugEnabled == true) {
                    WolfSSLDebug.log(getClass(), WolfSSLDebug.INFO,
                        "CB Read: returning WOLFSSL_CBIO_ERR_WANT_READ");
                }
                return WolfSSL.WOLFSSL_CBIO_ERR_WANT_READ;
            }

            max = (sz < this.netData.remaining()) ? sz : this.netData.remaining();
            this.netData.get(toRead, 0, max);

            if (ioDebugEnabled == true) {
                WolfSSLDebug.logHex(getClass(), WolfSSLDebug.INFO,
                                    "CB Read", toRead, max);
            }

            return max;
        }
    }

    private class SendCB implements WolfSSLIOSendCallback {

        protected SendCB() {

        }

        public int sendCallback(WolfSSLSession ssl, byte[] toSend, int sz,
                                Object engine) {
            return ((WolfSSLEngine)engine).internalSendCb(toSend, sz);
        }

    }

    private class RecvCB implements WolfSSLIORecvCallback {

        protected RecvCB() {

        }

        public int receiveCallback(WolfSSLSession ssl, byte[] out, int sz,
                                   Object engine) {
            return ((WolfSSLEngine)engine).internalRecvCb(out, sz);
        }

    }

    @SuppressWarnings("deprecation")
    @Override
    protected synchronized void finalize() throws Throwable {
        if (this.ssl != null) {
            this.ssl.freeSSL();
            this.ssl = null;
        }
        super.finalize();
    }
}

