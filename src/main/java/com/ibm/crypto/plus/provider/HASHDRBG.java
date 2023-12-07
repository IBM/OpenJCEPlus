/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.SecureRandomSpi;
import com.ibm.crypto.plus.provider.ock.BasicRandom;
import com.ibm.crypto.plus.provider.ock.ExtendedRandom;

abstract class HASHDRBG extends SecureRandomSpi {

    /**
     * 
     */

    private static final long serialVersionUID = 5913440825148411814L;

    private transient OpenJCEPlusProvider provider;
    private ProviderContext providerContext; // Keep track of which provider was used to create so can use for deserialization
    private String randomAlgo;

    private transient BasicRandom basicRandom;
    private transient ExtendedRandom extendedRandom;

    protected HASHDRBG(OpenJCEPlusProvider provider, String ockRandomAlgo) {
        this.provider = provider;
        this.providerContext = provider.getProviderContext();
        this.randomAlgo = ockRandomAlgo;
        basicRandom = BasicRandom.getInstance(provider.getOCKContext());
        try {
            extendedRandom = ExtendedRandom.getInstance(provider.getOCKContext(), ockRandomAlgo);
        } catch (Exception e) {
            throw provider.providerException("Failed to get HASHDRBG algorithm", e);
        }
    }

    @Override
    protected void engineSetSeed(byte[] seed) {
        try {
            extendedRandom.setSeed(seed);
        } catch (Exception e) {
            throw provider.providerException("Failed to set seed", e);
        }
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        if (bytes == null) {
            throw new NullPointerException("bytes is null"); // Required by JCK test NextBytes
        }
        try {
            extendedRandom.nextBytes(bytes);
        } catch (Exception e) {
            throw provider.providerException("Failed to get next bytes", e);
        }
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        try {
            return basicRandom.generateSeed(numBytes);
        } catch (Exception e) {
            throw provider.providerException("Failed to generate seed", e);
        }
    }

    /**
     * readObject is called to restore the state of this SecureRandom from a
     * stream.
     */
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Obtain the provider reference from the provider context
        //
        this.provider = providerContext.getProvider();

        // For testing purposes
        //
        //System.out.println("Restoring SecureRandom for " + randomAlgo + " from provider " + provider.getName());

        // Recreate OCK object per tag [SERIALIZATION] in DesignNotes.txt
        basicRandom = BasicRandom.getInstance(provider.getOCKContext());
        try {
            // Recreate OCK object per tag [SERIALIZATION] in DesignNotes.txt
            extendedRandom = ExtendedRandom.getInstance(provider.getOCKContext(), randomAlgo);
        } catch (Exception e) {
            throw provider.providerException("Failed to get HASHDRBG algorithm", e);
        }
    }

    // Nested class for SHA256DRBG
    public static final class SHA256DRBG extends HASHDRBG {

        private static final long serialVersionUID = 1035479890794113394L;

        public SHA256DRBG(OpenJCEPlusProvider provider) {
            super(provider, "SHA256");
        }
    }

    // Nested class for SHA512DRBG
    public static final class SHA512DRBG extends HASHDRBG {

        private static final long serialVersionUID = -7570316896850069363L;

        public SHA512DRBG(OpenJCEPlusProvider provider) {
            super(provider, "SHA512");
        }
    }
}
