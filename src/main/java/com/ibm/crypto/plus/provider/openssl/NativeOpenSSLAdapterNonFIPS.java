/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.openssl;

public class NativeOpenSSLAdapterNonFIPS extends NativeOpenSSLAdapter {
    private static NativeOpenSSLAdapterNonFIPS instance = null;

    private NativeOpenSSLAdapterNonFIPS() {
        super(false);
    }

    public static NativeOpenSSLAdapterNonFIPS getInstance() {
        System.out.println("Using OpenSSL non-FIPS adapter.");
        if (instance == null) {
            instance = new NativeOpenSSLAdapterNonFIPS();
        }

        return instance;
    }
}
