/* WolfSSLCustomUser.java
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
import  com.wolfssl.WolfSSL.TLS_VERSION;

/**
 * This class is intended to give some customization points to wolfJSSE
 * for users who want to hard-code certain limitations for wolfJSSE in terms
 * of protocol version support, cipher suite list, or native wolfSSL
 * SSL_NO_* type options.
 *
 * Most users will want to take other approaches to limiting these features,
 * as this approach will require modification of this class and a
 * recompilation/reinstallation of the wolfJSSE JAR file.
 *
 * Currently these limitations are enforced upon invocation of the
 * WolfSSLContext.init() method (createCtx()).
 *
 * @author  wolfSSL
 */
public class WolfSSLCustomUser {
    /** SSL/TLS version to be used with new SSLContext objects. */
    public TLS_VERSION version;
    /** String array of allowed cipher suites for new SSLContext objects */
    public String[] list;
    /** Mask of options to set for the associated native WOLFSSL_CTX */
    public long noOptions;

    /** Default WolfSSLCustomUser constructor */
    public WolfSSLCustomUser() { }

    /**
     * Factory method for getting SSLContext attributes before creating context,
     * TLS protocol and Cipher list. wolfJSSE calls this internally to get
     * values set below by the user, or passes defaults through from what
     * was otherwise going to be used by wolfJSSE when creating the SSLContext.
     *
     *      WARNING: Inappropriate code or use of this feature may cause
     *               serious security issues!
     *
     * @param version Default version of TLS for reference.
     * @param list    Default cipher list for reference.
     * @return        version: TLS protocol version to the context. The value
     *                         needs to be one compiled into native wolfSSL.
     *                list: Cipher list allowed for use in the SSLContext.
     *                      list needs to contain a subset of the default cipher
     *                      list. If it is null, default list is applied.
     */
    public static WolfSSLCustomUser GetCtxAttributes(TLS_VERSION version,
                                                     String[] list) {

        WolfSSLCustomUser ctxAttr = new WolfSSLCustomUser();

        /**
         Insert custom code here, and remove/modify defaults below.
         Example:
            ctxAttr.NoOptions = WolfSSL.SSL_OP_NO_TLSv1 | WolfSSL.SSL_OP_NO_TLSv1_3;
        */

        ctxAttr.version = version;
        ctxAttr.list   = list;
        ctxAttr.noOptions = 0;

        return ctxAttr;
    }
}
