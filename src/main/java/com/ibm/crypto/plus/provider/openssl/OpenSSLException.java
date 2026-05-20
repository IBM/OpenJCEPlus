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

    /* These codes are overriding the ones specified in the superclass NativeException
     * and must match those defined in native/openssl/ExceptionCodes.h.
     */
    public static final int GKR_FIPS_MODE_INVALID = 0x00000001;
    public static final int GKR_OCK_ATTACH_FAILED = 0x00000002;
    public static final int GKR_DECRYPT_FINAL_BAD_PADDING_ERROR = 0x00000003;
    public static final int GKR_UNSPECIFIED = 0x80000000;

    private static final Map<Integer, String> errorCodeMap = buildErrorCodeMap();

    private static Map<Integer, String> buildErrorCodeMap() {
        Hashtable<Integer, String> map = new Hashtable<Integer, String>();
        map.put(GKR_FIPS_MODE_INVALID, "FIPS mode invalid");
        map.put(GKR_OCK_ATTACH_FAILED, "ICC_Attach failed");
        return map;
    }

    public OpenSSLException(String s) {
        super(s);
        this.code = GKR_UNSPECIFIED;
    }

    public OpenSSLException(String s, Throwable cause) {
        super(s, cause);
        this.code = GKR_UNSPECIFIED;
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
