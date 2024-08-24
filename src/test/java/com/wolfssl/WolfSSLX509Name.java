/* WolfSSLX509Name.java
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
 * WolfSSLX509Name class, wraps native WOLFSSL_X509_NAME functionality.
 */
public class WolfSSLX509Name {

    private boolean active = false;
    private long x509NamePtr = 0;

    /* Lock around active state */
    private final Object stateLock = new Object();

    /* Lock around x509NamePtr pointer access */
    private final Object x509NameLock = new Object();

    /* Cache name elements in Java before pushing through JNI, for easier
     * retrieval from getXXX() methods */
    private String countryName               = null;
    private String stateOrProvinceName       = null;
    private String streetAddress             = null;
    private String localityName              = null;
    private String surname                   = null;
    private String commonName                = null;
    private String emailAddress              = null;
    private String organizationName          = null;
    private String organizationalUnitName    = null;
    private String postalCode                = null;
    private String userId                    = null;

    /* Encoding types, matched to native define values */
    private static final int MBSTRING_UTF8 = 0x100;

    /* Native JNI methods */
    static native long X509_NAME_new();
    static native void X509_NAME_free(long x509Name);
    static native int X509_NAME_add_entry_by_txt(long x509Name, String field,
        int type, byte[] entry, int len, int loc, int set);

    /**
     * Create new empty WolfSSLX509Name object.
     *
     * @throws WolfSSLException if native API call fails.
     */
    public WolfSSLX509Name() throws WolfSSLException {

        x509NamePtr = X509_NAME_new();
        if (x509NamePtr == 0) {
            throw new WolfSSLException("Failed to create WolfSSLX509Name");
        }

        synchronized (stateLock) {
            this.active = true;
        }
    }

    /**
     * Verifies that the current WolfSSLX509Name object is active.
     *
     * @throws IllegalStateException if object has been freed
     */
    private void confirmObjectIsActive()
        throws IllegalStateException {

        synchronized (stateLock) {
            if (this.active == false) {
                throw new IllegalStateException(
                    "WolfSSLX509Name object has been freed");
            }
        }
    }

    /**
     * For package use only, return native WOLFSSL_X509_NAME pointer.
     *
     * @return native WOLFSSL_X509_POINTER value
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    protected long getNativeX509NamePtr() throws IllegalStateException {

        confirmObjectIsActive();

        /* TODO lock around x509NamePtr for caller use */
        synchronized (x509NameLock) {
            return this.x509NamePtr;
        }
    }

    /**
     * Private helper function to call native JNI function
     * X509_NAME_add_entry_by_txt().
     *
     * @param field String containing field name to set, for example
     *              "countryName"
     * @param entry String value to store into field
     *
     * @throws WolfSSLException if arguments are invalid or error occurs
     *         with native JNI call.
     */
    private synchronized void addEntryByTxt(String field, String entry)
        throws WolfSSLException {

        int ret = 0;

        if (field == null || entry == null) {
            throw new WolfSSLException("field or entry is null in " +
                "addEntryByTxt()");
        }

        synchronized (x509NameLock) {
            ret = X509_NAME_add_entry_by_txt(this.x509NamePtr, field,
                    MBSTRING_UTF8, entry.getBytes(),
                    entry.getBytes().length, -1, 0);
        }

        if (ret != WolfSSL.SSL_SUCCESS) {
            throw new WolfSSLException("Error setting " + field + " into " +
                    "WolfSSLX509Name (error: " + ret + ")");
        }
    }

    /**
     * Set country name for this name object.
     *
     * @param countryName String containing country name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setCountryName(String countryName)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("countryName", countryName);
        this.countryName = countryName;
    }

    /**
     * Set state or province name for this name object.
     *
     * @param name String containing state or province name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setStateOrProvinceName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("stateOrProvinceName", name);
        this.stateOrProvinceName = name;
    }

    /**
     * Set street address for this name object.
     *
     * @param address String containing street address to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setStreetAddress(String address)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("streetAddress", address);
        this.streetAddress = address;
    }

    /**
     * Set locality name / city for this name object.
     *
     * @param name String containing locality name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setLocalityName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("localityName", name);
        this.localityName = name;
    }

    /**
     * Set surname for this name object.
     *
     * @param name String containing surname to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setSurname(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("surname", name);
        this.surname = name;
    }

    /**
     * Set common name for this name object.
     *
     * @param name String containing common name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setCommonName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("commonName", name);
        this.commonName = name;
    }

    /**
     * Set email address for this name object.
     *
     * @param email String containing email address to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setEmailAddress(String email)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("emailAddress", email);
        this.emailAddress = email;
    }

    /**
     * Set organization name for this name object.
     *
     * @param name String containing organization name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setOrganizationName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("organizationName", name);
        this.organizationName = name;
    }

    /**
     * Set organizational unit name for this name object.
     *
     * @param name String containing organizational unit name to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setOrganizationalUnitName(String name)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("organizationalUnitName", name);
        this.organizationalUnitName = name;
    }

    /**
     * Set postal code for this name object.
     *
     * @param code String containing postal code to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setPostalCode(String code)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("postalCode", code);
        this.postalCode = code;
    }

    /**
     * Set user ID for this name object.
     *
     * @param id String containing user ID to be set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     * @throws WolfSSLException if native JNI error has occurred, or input
     *         argument is invalid.
     */
    public synchronized void setUserId(String id)
        throws IllegalStateException, WolfSSLException {

        confirmObjectIsActive();

        addEntryByTxt("userId", id);
        this.userId = id;
    }

    /**
     * Get country name set in this object.
     *
     * @return country name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getCountryName() {

        confirmObjectIsActive();

        return this.countryName;
    }

    /**
     * Get state or province name set in this object.
     *
     * @return state or province name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getStateOrProvinceName() {

        confirmObjectIsActive();

        return this.stateOrProvinceName;
    }

    /**
     * Get street address set in this object.
     *
     * @return street address string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getStreetAddress() {

        confirmObjectIsActive();

        return this.streetAddress;
    }

    /**
     * Get locality name set in this object.
     *
     * @return locality name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getLocalityName() {

        confirmObjectIsActive();

        return this.localityName;
    }

    /**
     * Get surname set in this object.
     *
     * @return surname string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getSurname() {

        confirmObjectIsActive();

        return this.surname;
    }

    /**
     * Get common name set in this object.
     *
     * @return common name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getCommonName() {

        confirmObjectIsActive();

        return this.commonName;
    }

    /**
     * Get email address set in this object.
     *
     * @return email address string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getEmailAddress() {

        confirmObjectIsActive();

        return this.emailAddress;
    }

    /**
     * Get organization name set in this object.
     *
     * @return organization name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getOrganizationName() {

        confirmObjectIsActive();

        return this.organizationName;
    }

    /**
     * Get organizational unit name set in this object.
     *
     * @return organizational unit name string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getOrganizationalUnitName() {

        confirmObjectIsActive();

        return this.organizationalUnitName;
    }

    /**
     * Get postal code set in this object.
     *
     * @return postal code string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getPostalCode() {

        confirmObjectIsActive();

        return this.postalCode;
    }

    /**
     * Get user ID set in this object.
     *
     * @return user ID string, or null if not yet set
     *
     * @throws IllegalStateException if WolfSSLX509Name has been freed.
     */
    public synchronized String getUserId() {

        confirmObjectIsActive();

        return this.userId;
    }

    @Override
    public String toString() {

        synchronized (stateLock) {
            if (this.active == false) {
                return "";
            }
        }

        /* TODO: wrap wolfSSL_X509_NAME_oneline() */
        return null;
    }

    /**
     * Free native resources of WolfSSLX509Name.
     */
    public synchronized void free() {

        synchronized (stateLock) {
            if (this.active == false) {
                /* already freed, just return */
                return;
            }

            synchronized (x509NameLock) {
                /* free native resources */
                X509_NAME_free(this.x509NamePtr);

                this.active = false;
                this.x509NamePtr = 0;
            }
        }
    }

    @SuppressWarnings("deprecation")
    @Override
    protected void finalize() throws Throwable
    {
        this.free();
        super.finalize();
    }
}

