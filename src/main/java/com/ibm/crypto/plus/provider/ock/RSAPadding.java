/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public final class RSAPadding {

    public static final int RSAPAD_NONE = 0;
    public static final int RSAPAD_PKCS1 = 1;
    public static final int RSAPAD_OAEP = 2;
    //private static final int RSA_SSLV23_PADDING // Unused?
    //private static final int RSA_X931_PADDING // Unused?
    //private static final int RSA_PKCS1_PSS_PADDING // Unused?

    public static final RSAPadding NoPadding = new RSAPadding(RSAPAD_NONE, "NoPadding");
    public static final RSAPadding PKCS1Padding = new RSAPadding(RSAPAD_PKCS1, "PKCS1Padding");
    public static final RSAPadding OAEPPadding = new RSAPadding(RSAPAD_OAEP, "OAEPPadding");

    private int id;
    private String description;

    private RSAPadding(int id, String description) {
        this.id = id;
        this.description = description;
    }

    public int getId() {
        return id;
    }

    public boolean isPadding(int paddingId) {
        return id == paddingId;
    }

    public String toString() {
        return description;
    }
}
