/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;

public interface OJPKey {

    /**
     * Returns the native interface used by this key to perform operations
     * in the underlying cryptographic backend.
     *
     * @return the {@link NativeInterface} backing this key
     */
    public NativeInterface getBackendInterface();

    /**
     * Returns the provider associated with this key.
     *
     * @return the {@link OpenJCEPlusProvider} of this key
     */
    public OpenJCEPlusProvider getProvider();

    /**
     * Indicates whether this key was generated using a FIPS module.
     *
     * @return true if generated using a FIPS module, false otherwise
     */
    public boolean isFIPS();
}
