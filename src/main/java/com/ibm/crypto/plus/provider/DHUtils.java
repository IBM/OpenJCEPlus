/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidParameterException;

final class DHUtils {

    static final int MIN_KEYSIZE_NONFIPS = 512;
    static final int MAX_KEYSIZE_NONFIPS = 8192;
    static final int MIN_KEYSIZE_FIPS = 2048;
    static final int MAX_KEYSIZE_FIPS = 8192;

    /**
     * Validates the length of a DH key modulus and exponent to ensure it is
     * within the acceptable range.
     *
     * @param keySize
     *                the bit length of the modulus.
     * @param expSize
     *                the bit length of the exponent.
     * @param isFIPS
     *                indicates whether the provider is FIPS-compliant.
     * 
     * @throws InvalidParameterException
     *                             if any values are invalid.
     */
    static void checkKeySize(int keySize, int expSize, boolean isFIPS)
            throws InvalidParameterException {

        if (isFIPS) {
            checkKeySize(keySize, MIN_KEYSIZE_FIPS, MAX_KEYSIZE_FIPS, expSize);
        } else {
            checkKeySize(keySize, MIN_KEYSIZE_NONFIPS, MAX_KEYSIZE_NONFIPS, expSize);
        }
    }

    /**
     * Validates the length of a DH key modulus and exponent to ensure it falls
     * within the acceptable range. Some implementations may define their own
     * minimum and maximum key sizes, which may differ from system-defined values.
     *
     * @param keySize
     *                the bit length of the modulus.
     * @param minSize
     *                the minimum allowable length of the modulus.
     * @param maxSize
     *                the maximum allowable length of the modulus.
     * @param expSize
     *                the bit length of the exponent.
     *
     * @throws InvalidParameterException
     *                             if any values are invalid.
     */
    static void checkKeySize(int keySize, int minSize, int maxSize, int expSize)
            throws InvalidParameterException {

        if ((keySize < minSize) || (keySize > maxSize) || (keySize % 64 != 0)) {
            throw new InvalidParameterException(
                    "Invalid DH key size: " + keySize + ". It must be a multiple of 64 and " +
                            "within the range " + minSize + " - " + maxSize + " (inclusive).");
        }

        // expSize is optional and defaults to 0 if unspecified.
        if ((expSize < 0) || (expSize > keySize)) {
            throw new InvalidParameterException(
                    "Invalid exponent size: " + expSize + ". It must be non-negative and no larger " +
                    "than the key size (" + keySize + ").");
        }
    }
}
