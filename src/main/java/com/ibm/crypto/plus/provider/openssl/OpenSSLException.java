/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeException;
import java.util.Hashtable;
import java.util.Map;

public class OpenSSLException extends NativeException {

    /**
     *
     */
    private static final long serialVersionUID = -3104732494450550831L;

    /* These codes must match those defined in native/openssl/ExceptionCodes.h. */

    // General errors
    public static final int OPENSSL_FIPS_MODE_INVALID          = 0x00000001;
    public static final int OPENSSL_LIBRARY_LOAD_FAILED        = 0x00000002;
    public static final int OPENSSL_PROVIDER_LOAD_FAILED       = 0x00000003;
    public static final int OPENSSL_DIGEST_INIT_FAILED         = 0x00000004;
    public static final int OPENSSL_DIGEST_UPDATE_FAILED       = 0x00000005;
    public static final int OPENSSL_DIGEST_FINAL_FAILED        = 0x00000006;

    // Digest errors
    public static final int OPENSSL_DIGEST_NULL                = 0x0000000F;
    public static final int OPENSSL_DIGEST_INVALID             = 0x00000010;
    public static final int OPENSSL_DIGEST_ALGORITHM_NOT_FOUND = 0x00000011;
    public static final int OPENSSL_DIGEST_CTX_NEW_FAILED      = 0x00000012;
    public static final int OPENSSL_DIGEST_COPY_FAILED         = 0x00000013;

    // Random (SecureRandom / DRBG) errors
    public static final int OPENSSL_RAND_GENERATE_FAILED       = 0x00000030;
    public static final int OPENSSL_RAND_FETCH_FAILED          = 0x00000031;
    public static final int OPENSSL_RAND_CTX_NEW_FAILED        = 0x00000032;
    public static final int OPENSSL_RAND_INSTANTIATE_FAILED    = 0x00000033;
    public static final int OPENSSL_RAND_RESEED_FAILED         = 0x00000034;

    // Context / parameter errors
    public static final int OPENSSL_INVALID_PARAMETER          = 0x00000020;
    public static final int OPENSSL_ALLOCATION_FAILED          = 0x00000021;

    // Unspecified / generic
    public static final int OPENSSL_UNSPECIFIED                = 0x80000000;

    private static final Map<Integer, String> errorCodeMap = new Hashtable<Integer, String>();

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
        super(errorMessage(code));
        this.code = code;
    }

    private static String errorMessage(int code) {
        String message = errorCodeMap.get(Integer.valueOf(code));
        if (message == null) {
            message = "0x" + Integer.toHexString(code);
        }
        return message;
    }

}
