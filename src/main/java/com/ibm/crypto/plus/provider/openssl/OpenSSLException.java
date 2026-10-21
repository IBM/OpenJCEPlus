/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeException;

public class OpenSSLException extends NativeException {

    /**
     *
     */
    private static final long serialVersionUID = -3104732494450550831L;

    /*
     * Error codes exposed here are only those that Java logic must explicitly
     * branch on. Diagnostic codes used solely for error messages live in the
     * native layer (ExceptionCodes.h) and need not be mirrored in Java.
     */
    public static final int OPENSSL_UNSPECIFIED = 0x80000000;

    public OpenSSLException(String s) {
        super(s);
        this.code = OPENSSL_UNSPECIFIED;
    }

    public OpenSSLException(String s, Throwable cause) {
        super(s, cause);
        this.code = OPENSSL_UNSPECIFIED;
    }

    public OpenSSLException(String s, int code) {
        super(s);
        this.code = code;
    }

    public OpenSSLException(int code) {
        super("0x" + Integer.toHexString(code));
        this.code = code;
    }

}
