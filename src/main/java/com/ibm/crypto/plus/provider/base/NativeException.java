/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

/**
 * This is a class used for exceptions created by the native code that
 * utilizes the equivalent native libraries.
 *
 * The class can be subclassed by library-specific exception classes, or
 * be used directly by other classes who need to indicate that the problem
 * occured in native code, but might not have knowledge of the exact library
 * used.
 */
public class NativeException extends java.lang.Exception {

    private static final long serialVersionUID = 9223372036854775807L;

    protected int code = -1; // Non-specific value designed to be overriden.

    // These codes must be overriden by library-specific native exceptions.
    public static final int GKR_FIPS_MODE_INVALID = -1;
    public static final int GKR_OCK_ATTACH_FAILED = -1;
    public static final int GKR_DECRYPT_FINAL_BAD_PADDING_ERROR = -1;
    public static final int GKR_UNSPECIFIED = -1;

    public NativeException(String s) {
        super(s);
    }

    public NativeException(String s, Throwable cause) {
        super(s, cause);
    }

    public int getCode() {
        return code;
    }
}
