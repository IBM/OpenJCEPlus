/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import java.util.Hashtable;
import java.util.Map;

public final class OCKException extends java.lang.Exception {

    /**
     * 
     */
    private static final long serialVersionUID = -3104732494450550839L;

    // These codes must match those defined in ExceptionCodes.h.
    // 
    public static final int GKR_FIPS_MODE_INVALID = 0x00000001;
    public static final int GKR_OCK_ATTACH_FAILED = 0x00000002;
    public static final int GKR_DECRYPT_FINAL_BAD_PADDING_ERROR = 0x00000003;
    public static final int GKR_UNSPECIFIED = 0x80000000;

    private static final Map<Integer, String> errorCodeMap = buildErrorCodeMap();

    private int code;

    private static Map<Integer, String> buildErrorCodeMap() {
        Hashtable<Integer, String> map = new Hashtable<Integer, String>();
        map.put(GKR_FIPS_MODE_INVALID, "FIPS mode invalid");
        map.put(GKR_OCK_ATTACH_FAILED, "ICC_Attach failed");
        return map;
    }

    public OCKException(String s) {
        super(s);
        this.code = GKR_UNSPECIFIED;
    }

    public OCKException(String s, Throwable cause) {
        super(s, cause);
        this.code = GKR_UNSPECIFIED;
    }


    public OCKException(int code) {
        super(errorMessage(code));
        this.code = code;
    }

    public int getCode() {
        return code;
    }

    static String errorMessage(int code) {
        String message = errorCodeMap.get(Integer.valueOf(code));
        if (message == null) {
            message = "0x" + Integer.toHexString(code);
        }
        return message;
    }
}
