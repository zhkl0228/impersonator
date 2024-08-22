/* EccKey.java
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

import com.wolfssl.WolfSSLException;

/**
 * Wraps a native ecc_key structure pointer.
 *
 * @author  wolfSSL
 */
public class EccKey {

    /* internal ecc_key structure pointer */
    private long eccKeyPtr;

    /* is this key initialized, or has it been freed? */
    private boolean active = false;

    /**
     * Create new EccKey object, wrapping native ecc_key with pointer
     * keyPtr.
     *
     * @param keyPtr  pointer to native ecc_key structure
     * @throws com.wolfssl.WolfSSLException if key object creation failed
     */
    public EccKey(long keyPtr) throws WolfSSLException {
        if (keyPtr == 0) {
            throw new WolfSSLException("NULL ecc_key pointer not allowed");
        } else {
            this.active = true;
            this.eccKeyPtr = keyPtr;
        }
    }

    /* ------------------- private/protected methods -------------------- */

    long getEccKeyPtr() {
        return eccKeyPtr;
    }

    /* ------------------ native method declarations -------------------- */

    private native byte[] EccPublicKeyToDer(long eccKey);
    private native byte[] EccPrivateKeyToDer(long eccKey);
    private native byte[] EccPrivateKeyToPKCS8(long eccKey);

    /* ------------------- session-specific methods --------------------- */

    /**
     * Return ECC public key in DER format
     *
     * @return the raw ECC public key as a byte array.
     */
    public byte[] getPublicKeyDer() throws IllegalStateException {

        if (this.active == false)
            throw new IllegalStateException(
                    "Native ecc_key struct not initialized");

        return EccPublicKeyToDer(getEccKeyPtr());
    }

    /**
     * Return ECC private key in DER format
     *
     * @return the raw ECC private key as a byte array, not PKCS#8 formatted.
     */
    public byte[] getPrivateKeyDer() {

        if (this.active == false)
            throw new IllegalStateException(
                    "Native ecc_key struct not initialized");

        return EccPrivateKeyToDer(getEccKeyPtr());
    }

    /**
     * Return ECC private key DER in PKCS#8 format
     *
     * @return ECC private key DER in PKCS#8 format.
     */
    public byte[] getPrivateKeyPKCS8() {

        if (this.active == false)
            throw new IllegalStateException(
                    "Native ecc_key struct not initialized");

        return EccPrivateKeyToPKCS8(getEccKeyPtr());
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        if (this.active == true) {
            /* set state */
            this.active = false;
        }
        super.finalize();
    }

} /* end EccKey */

