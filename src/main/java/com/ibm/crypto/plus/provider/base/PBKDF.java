/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.base;

import com.ibm.crypto.plus.provider.OpenJCEPlusProvider;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterFIPS;
import com.ibm.crypto.plus.provider.ock.NativeOCKAdapterNonFIPS;

/**
 * Provides native implementations for password based key derivation related functions.
 */
public final class PBKDF {

    /**
     * Derives a key from a password using PBKDF2 defined
     * in PKCS#5 v2.0.
     * 
     * @param ockContext The OCKC context to use for deriving a key.
     * @param algorithmName The has to use in associated with PBDKF2, for example HmacSHA512.
     * @param password The password to derive a key from.
     * @param salt A salt
     * @param iterations The number of iterations to use when deriving the key.
     * @param keyLength The desired length of the key to be derived.
     * @return An array of bytes representing the key that was derived.
     * @throws NativeException If input parameters are incorrect or an error occurs in OCKC deriving the key.
     */
    public static byte[] PBKDF2derive(String algorithmName, final byte[] password,
            byte[] salt, int iterations, int keyLength, OpenJCEPlusProvider provider) throws NativeException {

        if ((!algorithmName.equalsIgnoreCase("HmacSHA512/224"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA512/256"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA512"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA384"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA256"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA224"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA1"))) {
            throw new NativeException("Algorithm name not recognized: " + algorithmName);
        }
        algorithmName = algorithmName.replace("/", "-");
        String algorithmHashName = algorithmName.substring(4).toUpperCase();

        if (keyLength <= 0) {
            throw new NativeException("Key length is less then or equal to 0");
        }

        if (algorithmName == null || algorithmName.isEmpty()) {
            throw new NativeException("Hash algorithm is null or empty");
        }

        if (password == null) {
            throw new NativeException("Password is null");
        }

        if ((salt == null) || (salt.length == 0)) {
            throw new NativeException("Salt is null or length 0");
        }

        if (iterations <= 0) {
            throw new NativeException("Iterations is less then or equal to 0");
        }

        NativeInterface nativeInterface = provider.isFIPS() ? NativeOCKAdapterFIPS.getInstance() : NativeOCKAdapterNonFIPS.getInstance();
        byte[] key = nativeInterface.PBKDF2_derive(algorithmHashName, password,
                salt, iterations, keyLength);

        if (null == key) {
            throw new NativeException("Error deriving key using PBKDF2. Key is null.");
        }

        return key;
    }
}
