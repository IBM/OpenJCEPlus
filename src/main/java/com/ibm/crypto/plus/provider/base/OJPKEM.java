/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

public final class OJPKEM {
    /*
     * ===========================================================================
     * Key Encapsulation interface to OCK.
     */

    public static void KEM_encapsulate(boolean isFIPS, long ockPKeyId, byte[] encapsulatedKey,
            byte[] keyMaterial) throws OCKException {
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        nativeImpl.KEM_encapsulate(ockPKeyId, encapsulatedKey, keyMaterial);
    }

    public static byte[] KEM_decapsulate(boolean isFIPS, long ockPKeyId, byte[] encapsulatedKey)
            throws OCKException {
        NativeInterface nativeImpl = NativeInterfaceFactory.getImpl(isFIPS);
        byte[] keyMaterial = nativeImpl.KEM_decapsulate(ockPKeyId, encapsulatedKey);
        return keyMaterial;
    }

}
