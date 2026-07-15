/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

public final class OJPKEM {
    /*
     * ===========================================================================
     * Key Encapsulation interface to OCK.
     */

    public static void KEM_encapsulate(long ockPKeyId, byte[] encapsulatedKey,
            byte[] keyMaterial, OpenJCEPlusProvider provider, String algName) throws NativeException {
        NativeInterface nativeInterface = NativeCryptoSelector.selectBackend(provider, "KEM", algName);
        nativeInterface.KEM_encapsulate(ockPKeyId, encapsulatedKey, keyMaterial);
    }

    public static byte[] KEM_decapsulate(long ockPKeyId, byte[] encapsulatedKey, OpenJCEPlusProvider provider,
            String algName) throws NativeException {
        NativeInterface nativeInterface = NativeCryptoSelector.selectBackend(provider, "KEM", algName);
        byte[] keyMaterial = nativeInterface.KEM_decapsulate(ockPKeyId, encapsulatedKey);

        return keyMaterial;
    }

}
