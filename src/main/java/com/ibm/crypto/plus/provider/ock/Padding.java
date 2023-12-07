/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

public final class Padding {

    // These code values must match those defined in Padding.h.
    //
    public static final int PADDING_NONE = 0;
    public static final int PADDING_PKCS5 = 1;

    public static final Padding NoPadding = new Padding(PADDING_NONE, "NoPadding");
    public static final Padding PKCS5Padding = new Padding(PADDING_PKCS5, "PKCS5Padding");

    private int id;
    private String description;

    private Padding(int id, String description) {
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
