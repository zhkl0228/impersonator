/* ECC.java
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
 * Wrapper for the native WolfCrypt ECC implementation, used for examples.
 * This class contains a subset of the WolfCrypt ECC implementation and was
 * written to be used with this package's example ECC public key callbacks.
 * Usage can be found in examples/Client.java and examples/Server.java.
 *
 * @author  wolfSSL
 */
public class ECC {

    /** Default ECC constructor */
    public ECC() { }

    /**
     * ECC verify. Wraps native wc_ecc_verify_hash() to verify ECDSA
     * signature against known hash value.
     *
     * @param sig input ByteBuffer to be verified
     * @param sigSz size of input buffer, bytes
     * @param hash input hash to compare signature against
     * @param hashLen size of input hash, bytes
     * @param keyDer public key to use for verify, DER format
     * @param keySz size of keyDer, bytes
     * @param result first array element set to 0 on successful verify
     *
     * @return 0 on success, negative on error.
     */
    public native int doVerify(ByteBuffer sig, long sigSz, ByteBuffer hash,
            long hashLen, ByteBuffer keyDer, long keySz, int[] result);

    /**
     * ECC sign. Wraps native wolfCrypt wc_ecc_sign_hash() to
     * sign input hash with ECDSA.
     *
     * Currently only used with public key callbacks.
     *
     * @param in input ByteBuffer to be signed
     * @param inSz size of input, bytes
     * @param out ByteBuffer to place output signature
     * @param outSz [IN/OUT] size of output buffer on input, size of
     *              generated signature on return.
     * @param key ByteBuffer holding DER encoded ECC key
     * @param keySz size of input key, bytes
     *
     * @return 0 on success, negative on error.
     */
    public native int doSign(ByteBuffer in, long inSz, ByteBuffer out,
            long[] outSz, ByteBuffer key, long keySz);

}

