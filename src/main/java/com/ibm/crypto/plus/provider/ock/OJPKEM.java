/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

public final class OJPKEM {
    /*
     * ===========================================================================
     * Key Encapsulation interface to OCK.
     */

    public static void KEM_encapsulate(OCKContext ockContext, long ockPKeyId, byte[] encapsulatedKey,
            byte[] keyMaterial) throws OCKException {
        NativeInterface.KEM_encapsulate(ockContext.getId(), ockPKeyId, encapsulatedKey, keyMaterial);
    }

    public static byte[] KEM_decapsulate(OCKContext ockContext, long ockPKeyId, byte[] encapsulatedKey)
            throws OCKException {
        byte[] keyMaterial = 
            NativeInterface.KEM_decapsulate(ockContext.getId(), ockPKeyId, encapsulatedKey);

        return keyMaterial;
    }

}
