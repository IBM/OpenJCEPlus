/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

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
