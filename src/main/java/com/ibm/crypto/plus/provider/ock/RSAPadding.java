/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
