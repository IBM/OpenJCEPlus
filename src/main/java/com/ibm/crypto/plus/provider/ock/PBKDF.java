/*
 * Copyright IBM Corp. 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider.ock;

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
     * @throws OCKException If input parameters are incorrect or an error occurs in OCKC deriving the key.
     */
    public static byte[] PBKDF2derive(OCKContext ockContext, String algorithmName,
            final byte[] password, byte[] salt, int iterations, int keyLength) throws OCKException {

        if ((!algorithmName.equalsIgnoreCase("HmacSHA512"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA384"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA256"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA224"))
                && (!algorithmName.equalsIgnoreCase("HmacSHA1"))) {
            throw new OCKException("Algorithm name not recognized: " + algorithmName);
        }
        String algorithmHashName = algorithmName.substring(4).toUpperCase();

        if (keyLength <= 0) {
            throw new OCKException("Key length is less then or equal to 0");
        }

        if (ockContext == null) {
            throw new OCKException("Context is null");
        }

        if (algorithmName == null || algorithmName.isEmpty()) {
            throw new OCKException("Hash algorithm is null or empty");
        }

        if (password == null) {
            throw new OCKException("Password is null");
        }

        if ((salt == null) || (salt.length == 0)) {
            throw new OCKException("Salt is null or length 0");
        }

        if (iterations <= 0) {
            throw new OCKException("Iterations is less then or equal to 0");
        }

        byte[] key = NativeInterface.PBKDF2_derive(ockContext.getId(), algorithmHashName, password,
                salt, iterations, keyLength);

        if (null == key) {
            throw new OCKException("Error deriving key using PBKDF2. Key is null.");
        }

        return key;
    }
}
