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

    /** Generic error code set on all OpenSSLException instances. */
    public static final int OPENSSL_UNSPECIFIED = 0x80000000;

    public OpenSSLException(String s) {
        super(s);
        this.code = OPENSSL_UNSPECIFIED;
    }

    public OpenSSLException(String s, Throwable cause) {
        super(s, cause);
        this.code = OPENSSL_UNSPECIFIED;
    }

    public OpenSSLException(int code) {
        super("0x" + Integer.toHexString(code));
        this.code = code;
    }

}
