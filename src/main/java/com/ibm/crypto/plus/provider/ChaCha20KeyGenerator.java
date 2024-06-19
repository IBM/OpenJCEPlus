/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/**
 * This class generates a secret key for use with the ChaCha20 algorithm.
 */
public final class ChaCha20KeyGenerator extends KeyGeneratorSpi implements ChaCha20Constants {

    private OpenJCEPlusProvider provider = null;
    private int keysize = ChaCha20_KEY_SIZE;
    private SecureRandom cryptoRandom;

    /**
     * Empty constructor
     */
    public ChaCha20KeyGenerator(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    /**
     * Generates an ChaCha20 key.
     *
     * @return the new ChaCha20 key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (this.cryptoRandom == null) {
            this.cryptoRandom = provider.getSecureRandom(null);
        }

        byte[] keyBytes = new byte[this.keysize];
        this.cryptoRandom.nextBytes(keyBytes);

        try {
            return new ChaCha20Key(keyBytes);
        } catch (InvalidKeyException e) {
            // Should never happen
            throw new ProviderException(e.getMessage());
        } finally {
            // fill keybytes with 0x00 - FIPS requirement to reset arrays that
            // got filled with random bytes from random
            Arrays.fill(keyBytes, (byte) 0x00);
        }
    }

    /**
     * Initializes this key generator.
     * 
     * @param random
     *            the source of randomness for this generator
     */
    @Override
    protected void engineInit(SecureRandom random) {
        // If in FIPS mode, SecureRandom must be internal and FIPS approved.
        // For FIPS mode, user provided random generator will be ignored.
        //
        this.cryptoRandom = provider.getSecureRandom(random);
    }

    /**
     * Initializes this key generator with the specified parameter set and a
     * user-provided source of randomness.
     *
     * @param params
     *            the key generation parameters
     * @param random
     *            the source of randomness for this key generator
     *
     * @exception InvalidAlgorithmParameterException
     *                if <code>params</code> is inappropriate for this key
     *                generator
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "ChaCha20 key generation does not take any parameters");
    }

    /**
     * Initializes this key generator for a certain keysize, using the given
     * source of randomness.
     *
     * @param keysize
     *            the keysize. This is an algorithm-specific metric specified in
     *            number of bits.
     * @param random
     *            the source of randomness for this key generator
     */
    @Override
    protected void engineInit(int keysize, SecureRandom random) {

        int keysizeBytes = keysize / 8;

        if (keysizeBytes != ChaCha20_KEY_SIZE) {
            throw new InvalidParameterException("Key must be " + ChaCha20_KEY_SIZE + " bytes");
        }

        this.keysize = keysizeBytes;
        this.engineInit(random);
    }
}
