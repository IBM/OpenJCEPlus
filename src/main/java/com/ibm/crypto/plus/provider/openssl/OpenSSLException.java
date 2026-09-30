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

    // HMAC error codes
    public static final int OPENSSL_HMAC_NULL                   = 0x00000014;
    public static final int OPENSSL_HMAC_INVALID                = 0x00000015;
    public static final int OPENSSL_HMAC_CTX_NEW_FAILED         = 0x00000016;
    public static final int OPENSSL_HMAC_INIT_FAILED            = 0x00000017;
    public static final int OPENSSL_HMAC_UPDATE_FAILED          = 0x00000018;
    public static final int OPENSSL_HMAC_FINAL_FAILED           = 0x00000019;

    // KDF error codes
    public static final int OPENSSL_PBKDF2_FAILED               = 0x0000001A;
    public static final int OPENSSL_HKDF_EXTRACT_FAILED         = 0x0000001B;
    public static final int OPENSSL_HKDF_EXPAND_FAILED          = 0x0000001C;
    public static final int OPENSSL_HKDF_DERIVE_FAILED          = 0x0000001D;

    // Context / parameter error codes
    public static final int OPENSSL_CONTEXT_INIT_FAILED         = 0x0000001E;
    public static final int OPENSSL_CONTEXT_NULL                = 0x0000001F;
    public static final int OPENSSL_INVALID_PARAMETER           = 0x00000020;
    public static final int OPENSSL_ALLOCATION_FAILED           = 0x00000021;

    // Signature error codes
    public static final int OPENSSL_SIGNATURE_NULL              = 0x00000022;
    public static final int OPENSSL_SIGNATURE_INVALID           = 0x00000023;
    public static final int OPENSSL_SIGNATURE_KEY_LOAD_FAILED   = 0x00000024;
    public static final int OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND = 0x00000025;
    public static final int OPENSSL_SIGNATURE_CTX_NEW_FAILED    = 0x00000026;
    public static final int OPENSSL_SIGNATURE_INIT_FAILED       = 0x00000027;
    public static final int OPENSSL_SIGNATURE_UPDATE_FAILED     = 0x00000028;
    public static final int OPENSSL_SIGNATURE_SIGN_FAILED       = 0x00000029;
    public static final int OPENSSL_SIGNATURE_VERIFY_FAILED     = 0x0000002A;
    public static final int OPENSSL_SIGNATURE_PSS_PARAM_FAILED  = 0x0000002B;

    // Key pair generation error codes
    public static final int OPENSSL_KEYPAIRGEN_NULL             = 0x0000002C;
    public static final int OPENSSL_KEYPAIRGEN_INVALID          = 0x0000002D;
    public static final int OPENSSL_KEYPAIRGEN_ALLOC_FAILED     = 0x0000002E;
    public static final int OPENSSL_KEYPAIRGEN_CREATE_FAILED    = 0x0000002F;
    public static final int OPENSSL_KEYPAIRGEN_INIT_FAILED      = 0x00000030;
    public static final int OPENSSL_KEYPAIRGEN_INVALID_PARAM    = 0x00000031;
    public static final int OPENSSL_KEYPAIRGEN_PARAM_FAILED     = 0x00000032;
    public static final int OPENSSL_KEYPAIRGEN_GENERATE_FAILED  = 0x00000033;
    public static final int OPENSSL_KEYPAIRGEN_ENCODE_FAILED    = 0x00000034;

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
        this.errorCode = 0;
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
            case OPENSSL_HMAC_NULL:                   return "OPENSSL_HMAC_NULL";
            case OPENSSL_HMAC_INVALID:                return "OPENSSL_HMAC_INVALID";
            case OPENSSL_HMAC_CTX_NEW_FAILED:         return "OPENSSL_HMAC_CTX_NEW_FAILED";
            case OPENSSL_HMAC_INIT_FAILED:            return "OPENSSL_HMAC_INIT_FAILED";
            case OPENSSL_HMAC_UPDATE_FAILED:          return "OPENSSL_HMAC_UPDATE_FAILED";
            case OPENSSL_HMAC_FINAL_FAILED:           return "OPENSSL_HMAC_FINAL_FAILED";
            case OPENSSL_PBKDF2_FAILED:               return "OPENSSL_PBKDF2_FAILED";
            case OPENSSL_HKDF_EXTRACT_FAILED:         return "OPENSSL_HKDF_EXTRACT_FAILED";
            case OPENSSL_HKDF_EXPAND_FAILED:          return "OPENSSL_HKDF_EXPAND_FAILED";
            case OPENSSL_HKDF_DERIVE_FAILED:          return "OPENSSL_HKDF_DERIVE_FAILED";
            case OPENSSL_CONTEXT_INIT_FAILED:         return "OPENSSL_CONTEXT_INIT_FAILED";
            case OPENSSL_CONTEXT_NULL:                return "OPENSSL_CONTEXT_NULL";
            case OPENSSL_INVALID_PARAMETER:           return "OPENSSL_INVALID_PARAMETER";
            case OPENSSL_ALLOCATION_FAILED:           return "OPENSSL_ALLOCATION_FAILED";
            case OPENSSL_SIGNATURE_NULL:              return "OPENSSL_SIGNATURE_NULL";
            case OPENSSL_SIGNATURE_INVALID:           return "OPENSSL_SIGNATURE_INVALID";
            case OPENSSL_SIGNATURE_KEY_LOAD_FAILED:   return "OPENSSL_SIGNATURE_KEY_LOAD_FAILED";
            case OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND: return "OPENSSL_SIGNATURE_ALGORITHM_NOT_FOUND";
            case OPENSSL_SIGNATURE_CTX_NEW_FAILED:    return "OPENSSL_SIGNATURE_CTX_NEW_FAILED";
            case OPENSSL_SIGNATURE_INIT_FAILED:       return "OPENSSL_SIGNATURE_INIT_FAILED";
            case OPENSSL_SIGNATURE_UPDATE_FAILED:     return "OPENSSL_SIGNATURE_UPDATE_FAILED";
            case OPENSSL_SIGNATURE_SIGN_FAILED:       return "OPENSSL_SIGNATURE_SIGN_FAILED";
            case OPENSSL_SIGNATURE_VERIFY_FAILED:     return "OPENSSL_SIGNATURE_VERIFY_FAILED";
            case OPENSSL_SIGNATURE_PSS_PARAM_FAILED:  return "OPENSSL_SIGNATURE_PSS_PARAM_FAILED";
            case OPENSSL_KEYPAIRGEN_NULL:             return "OPENSSL_KEYPAIRGEN_NULL";
            case OPENSSL_KEYPAIRGEN_INVALID:          return "OPENSSL_KEYPAIRGEN_INVALID";
            case OPENSSL_KEYPAIRGEN_ALLOC_FAILED:     return "OPENSSL_KEYPAIRGEN_ALLOC_FAILED";
            case OPENSSL_KEYPAIRGEN_CREATE_FAILED:    return "OPENSSL_KEYPAIRGEN_CREATE_FAILED";
            case OPENSSL_KEYPAIRGEN_INIT_FAILED:      return "OPENSSL_KEYPAIRGEN_INIT_FAILED";
            case OPENSSL_KEYPAIRGEN_INVALID_PARAM:    return "OPENSSL_KEYPAIRGEN_INVALID_PARAM";
            case OPENSSL_KEYPAIRGEN_PARAM_FAILED:     return "OPENSSL_KEYPAIRGEN_PARAM_FAILED";
            case OPENSSL_KEYPAIRGEN_GENERATE_FAILED:  return "OPENSSL_KEYPAIRGEN_GENERATE_FAILED";
            case OPENSSL_KEYPAIRGEN_ENCODE_FAILED:    return "OPENSSL_KEYPAIRGEN_ENCODE_FAILED";
            case OPENSSL_UNSPECIFIED:                 return "OPENSSL_UNSPECIFIED";
            default:                                  return "UNKNOWN_ERROR_CODE_0x" + Integer.toHexString(code);
        }
    }

    public String getErrorCodeString() {
        return getErrorCodeString(errorCode);
    }

}
