/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

import com.ibm.crypto.plus.provider.base.NativeException;

/**
 * Exception thrown by OpenSSL native operations.
 * Error codes mirror the constants defined in {@code OpenSSLExceptionCodes.h}.
 */
public class OpenSSLException extends NativeException {
    private static final long serialVersionUID = 1L;

    // These must match the values in OpenSSLExceptionCodes.h
    /** Sentinel for exceptions constructed without an explicit error code. */
    public static final int OPENSSL_NO_ERROR_CODE               = 0x00000000;
    public static final int OPENSSL_FIPS_MODE_INVALID           = 0x00000001;
    public static final int OPENSSL_LIBRARY_LOAD_FAILED         = 0x00000002;
    public static final int OPENSSL_PROVIDER_LOAD_FAILED        = 0x00000003;
    public static final int OPENSSL_DIGEST_INIT_FAILED          = 0x00000004;
    public static final int OPENSSL_DIGEST_UPDATE_FAILED        = 0x00000005;
    public static final int OPENSSL_DIGEST_FINAL_FAILED         = 0x00000006;
    public static final int OPENSSL_RAND_SEED_FAILED            = 0x00000007;
    public static final int OPENSSL_RAND_BYTES_FAILED           = 0x00000008;
    public static final int OPENSSL_CIPHER_INIT_FAILED          = 0x00000009;
    public static final int OPENSSL_CIPHER_UPDATE_FAILED        = 0x0000000A;
    public static final int OPENSSL_CIPHER_FINAL_FAILED         = 0x0000000B;
    // 0x0000000C and 0x0000000D are reserved for future use
    public static final int OPENSSL_CIPHER_TAG_MISMATCH         = 0x0000000E;

    // Digest error codes
    public static final int OPENSSL_DIGEST_NULL                 = 0x0000000F;
    public static final int OPENSSL_DIGEST_INVALID              = 0x00000010;
    public static final int OPENSSL_DIGEST_ALGORITHM_NOT_FOUND  = 0x00000011;
    public static final int OPENSSL_DIGEST_CTX_NEW_FAILED       = 0x00000012;
    public static final int OPENSSL_DIGEST_COPY_FAILED          = 0x00000013;

    // Context / parameter error codes
    public static final int OPENSSL_CONTEXT_INIT_FAILED         = 0x0000001E;
    public static final int OPENSSL_CONTEXT_NULL                = 0x0000001F;
    public static final int OPENSSL_INVALID_PARAMETER           = 0x00000020;
    public static final int OPENSSL_ALLOCATION_FAILED           = 0x00000021;

    public static final int OPENSSL_UNSPECIFIED                 = 0x80000000;

    private int errorCode;

    public OpenSSLException(String message) {
        super(message);
        this.errorCode = OPENSSL_NO_ERROR_CODE;
    }

    public OpenSSLException(String message, int errorCode) {
        super(message + " (Error code: " + errorCode + " - " + getErrorCodeString(errorCode) + ")");
        this.errorCode = errorCode;
    }

    public OpenSSLException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = OPENSSL_NO_ERROR_CODE;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public static String getErrorCodeString(int code) {
        switch (code) {
            case OPENSSL_NO_ERROR_CODE:               return "OPENSSL_NO_ERROR_CODE";
            case OPENSSL_FIPS_MODE_INVALID:           return "OPENSSL_FIPS_MODE_INVALID";
            case OPENSSL_LIBRARY_LOAD_FAILED:         return "OPENSSL_LIBRARY_LOAD_FAILED";
            case OPENSSL_PROVIDER_LOAD_FAILED:        return "OPENSSL_PROVIDER_LOAD_FAILED";
            case OPENSSL_DIGEST_INIT_FAILED:          return "OPENSSL_DIGEST_INIT_FAILED";
            case OPENSSL_DIGEST_UPDATE_FAILED:        return "OPENSSL_DIGEST_UPDATE_FAILED";
            case OPENSSL_DIGEST_FINAL_FAILED:         return "OPENSSL_DIGEST_FINAL_FAILED";
            case OPENSSL_RAND_SEED_FAILED:            return "OPENSSL_RAND_SEED_FAILED";
            case OPENSSL_RAND_BYTES_FAILED:           return "OPENSSL_RAND_BYTES_FAILED";
            case OPENSSL_CIPHER_INIT_FAILED:          return "OPENSSL_CIPHER_INIT_FAILED";
            case OPENSSL_CIPHER_UPDATE_FAILED:        return "OPENSSL_CIPHER_UPDATE_FAILED";
            case OPENSSL_CIPHER_FINAL_FAILED:         return "OPENSSL_CIPHER_FINAL_FAILED";
            case OPENSSL_CIPHER_TAG_MISMATCH:         return "OPENSSL_CIPHER_TAG_MISMATCH";
            case OPENSSL_DIGEST_NULL:                 return "OPENSSL_DIGEST_NULL";
            case OPENSSL_DIGEST_INVALID:              return "OPENSSL_DIGEST_INVALID";
            case OPENSSL_DIGEST_ALGORITHM_NOT_FOUND:  return "OPENSSL_DIGEST_ALGORITHM_NOT_FOUND";
            case OPENSSL_DIGEST_CTX_NEW_FAILED:       return "OPENSSL_DIGEST_CTX_NEW_FAILED";
            case OPENSSL_DIGEST_COPY_FAILED:          return "OPENSSL_DIGEST_COPY_FAILED";
            case OPENSSL_CONTEXT_INIT_FAILED:         return "OPENSSL_CONTEXT_INIT_FAILED";
            case OPENSSL_CONTEXT_NULL:                return "OPENSSL_CONTEXT_NULL";
            case OPENSSL_INVALID_PARAMETER:           return "OPENSSL_INVALID_PARAMETER";
            case OPENSSL_ALLOCATION_FAILED:           return "OPENSSL_ALLOCATION_FAILED";
            case OPENSSL_UNSPECIFIED:                 return "OPENSSL_UNSPECIFIED";
            default:                                  return "UNKNOWN_ERROR_CODE_0x" + Integer.toHexString(code);
        }
    }

    public String getErrorCodeString() {
        return getErrorCodeString(errorCode);
    }

}
