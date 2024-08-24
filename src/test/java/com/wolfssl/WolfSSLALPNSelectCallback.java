/* WolfSSLALPNSelectCallback.java
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
 * wolfSSL ALPN Select Callback Interface.
 * This interface specifies how applications should implement the ALPN
 * select callback class to be used by wolfSSL.
 * <p>
 * After implementing this interface, it should be passed as a parameter
 * to the {@link WolfSSLSession#setAlpnSelectCb(WolfSSLALPNSelectCallback,
 * Object) WolfSSLSession.setALPNSelectCb()} method to be registered with the
 * native wolfSSL session.
 *
 * @author wolfSSL
 */
public interface WolfSSLALPNSelectCallback {

    /**
     * ALPN select callback method.
     * This method acts as the selection callback for Application Layer
     * Negotiation Protocol (ALPN). This will be called during the handshake
     * and gives the ALPN protocols proposed by the peer, allowing the server
     * to select the desired protocol.
     *
     * @param ssl the current SSL session object from which the callback was
     *            initiated.
     * @param out output array; the selected ALPN protocol should be placed as
     *            a String into the first array element, ie out[0].
     * @param in  input array containing the ALPN values sent by the client
     *            in the ClientHello message.
     * @param arg Object set by user when registering callback, passed back
     *            to user inside callback in case needed to select ALPN.
     * @return WolfSSL.SSL_TLSEXT_ERR_OK if ALPN protocol has been selected,
     *         WolfSSL.SSL_TLSEXT_ERR_NOACK if ALPN protocol was not selected
     *             but handshake should proceed without ALPN,
     *         WolfSSL.SSL_TLSEXT_ERR_ALERT_FATAL if no ALPN match can be found
     *             and a fatal alert should be sent to peer to end the
     *             handshake.
     */
    public int alpnSelectCallback(WolfSSLSession ssl, String[] out,
        String[] in, Object arg);
}

