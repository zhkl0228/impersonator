/* RSA.java
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

package com.wolfssl.wolfcrypt;

import java.nio.ByteBuffer;

/**
 * Wrapper for the native WolfCrypt RSA implementation, used for examples.
 * This class contains a subset of the WolfCrypt RSA implementation and was
 * written to be used with this package's example RSA public key callbacks.
 * Usage can be found in examples/Client.java and examples/Server.java.
 *
 * @author  wolfSSL
 */
public class RSA {

    /** Default RSA constructor */
    public RSA() { }

    /**
     * RSA sign, wraps native wolfCrypt operation.
     *
     * @param in input buffer to be signed
     * @param inSz size of input buffer, bytes
     * @param out output for generated signature
     * @param outSz [IN/OUT] size of output buffer on input, size of
     *              generated signature on output
     * @param key DER formatted RSA key to be used for signing
     * @param keySz size of key, bytes
     *
     * @return 0 on success, negative on error.
     */
    public native int doSign(ByteBuffer in, long inSz, ByteBuffer out,
            int[] outSz, ByteBuffer key, long keySz);

    /**
     * RSA verify, wraps native wolfCrypt operation.
     *
     * @param sig input signature to verify
     * @param sigSz size of input signature, bytes
     * @param out output buffer to place signed data
     * @param outSz size of output buffer, bytes
     * @param keyDer public key used for verify, DER formatted
     * @param keySz size of public key, bytes
     *
     * @return size of returned data on success, negative on error.
     */
    public native int doVerify(ByteBuffer sig, long sigSz, ByteBuffer out,
           long outSz, ByteBuffer keyDer, long keySz);

    /**
     * RSA encrypt, wraps native wolfCrypt operation.
     *
     * @param in input data to be encrypted
     * @param inSz size of input data, bytes
     * @param out output buffer to place encrypted result
     * @param outSz [IN/OUT] size of output buffer on input, size of
     *              encrypted data on return
     * @param keyDer RSA key used for encrypt, DER formatted
     * @param keySz size of RSA key, bytes
     *
     * @return 0 on success, negative on error
     */
    public native int doEnc(ByteBuffer in, long inSz, ByteBuffer out,
            int[] outSz, ByteBuffer keyDer, long keySz);

    /**
     * RSA decrypt, wraps native wolfCrypt operation.
     *
     * @param in input buffer to decrypt
     * @param inSz size of input buffer, bytes
     * @param out output buffer for decrypted data
     * @param outSz size of output buffer, bytes
     * @param keyDer RSA key used for decryption, DER formatted
     * @param keySz size of RSA key, bytes
     *
     * @return size of decrypted data on success, negative on error.
     */
    public native int doDec(ByteBuffer in, long inSz, ByteBuffer out,
            long outSz, ByteBuffer keyDer, long keySz);
}

