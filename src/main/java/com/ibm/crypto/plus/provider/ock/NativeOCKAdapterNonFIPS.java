/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public class NativeOCKAdapterNonFIPS extends NativeOCKAdapter {
    private static NativeOCKAdapterNonFIPS instance = null;

    private NativeOCKAdapterNonFIPS() {
        super(false);
    }

    public static NativeOCKAdapterNonFIPS getInstance() {
        if (instance == null) {
            instance = new NativeOCKAdapterNonFIPS();
        }

        return instance;
    }

}
