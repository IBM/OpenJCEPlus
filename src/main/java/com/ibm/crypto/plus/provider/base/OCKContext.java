/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public final class OCKContext {
    // These code values must match those defined in Context.h.
    //
    private static final int VALUE_ID_FIPS_APPROVED_MODE = 0;
    private static final int VALUE_OCK_INSTALL_PATH = 1;
    private static final int VALUE_OCK_VERSION = 2;

    // The following is a special String instance to indicate that a
    // value has not yet been obtained.  We do this because some values
    // may be null and we only want to query the value one time.
    //
    static final String unobtainedValue = new String();

    // whether to validate OCK was loaded from JRE location
    private static final boolean validateOCKLocation = true;

    // whether to validate OCK version of load library matches version in ICCSIG.txt
    private static final boolean validateOCKVersion = false;

    private long ockContextId;
    private boolean isFIPS;
    private String ockVersion = unobtainedValue;
    private String ockInstallPath = unobtainedValue;

    private static String libraryBuildDate = unobtainedValue;

    public static OCKContext createContext(boolean isFIPS) throws OCKException {
        long ockContextId = NativeInterface.initializeOCK(isFIPS);

        OCKContext context = new OCKContext(ockContextId, isFIPS);

        if (validateOCKLocation) {
            NativeInterface.validateLibraryLocation(context);
        }

        if (validateOCKVersion) {
            NativeInterface.validateLibraryVersion(context);
        }

        return context;
    }

    private OCKContext(long ockContextId, boolean isFIPS) {
        this.ockContextId = ockContextId;
        this.isFIPS = isFIPS;
    }

    public long getId() {
        return ockContextId;
    }

    public boolean isFIPS() {
        return isFIPS;
    }

    public String getOCKVersion() throws OCKException {
        if (ockVersion == unobtainedValue) {
            obtainOCKVersion();
        }
        return ockVersion;
    }

    public String getOCKInstallPath() throws OCKException {
        if (ockInstallPath == unobtainedValue) {
            obtainOCKInstallPath();
        }
        return ockInstallPath;
    }

    public static String getLibraryBuildDate() {
        if (libraryBuildDate == unobtainedValue) {
            obtainLibraryBuildDate();
        }
        return libraryBuildDate;
    }

    private synchronized void obtainOCKVersion() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (ockVersion == unobtainedValue) {
            ockVersion = getValue(VALUE_OCK_VERSION);
        }
    }

    private synchronized void obtainOCKInstallPath() throws OCKException {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (ockInstallPath == unobtainedValue) {
            ockInstallPath = getValue(VALUE_OCK_INSTALL_PATH);
        }
    }

    private synchronized static void obtainLibraryBuildDate() {
        // Leave this duplicate check in here. If two threads are both trying
        // to get the value at the same time, we only want to call the native
        // code one time.
        //
        if (libraryBuildDate == unobtainedValue) {
            libraryBuildDate = NativeInterface.getLibraryBuildDate();
        }
    }

    private String getValue(int valueId) throws OCKException {
        return NativeInterface.CTX_getValue(ockContextId, valueId);
    }

    public String toString() {
        return "OCKContext [isFIPS=" + isFIPS + ", id=" + ockContextId + "]";
    }
}
