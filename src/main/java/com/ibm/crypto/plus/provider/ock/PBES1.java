/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider.ock;

/**
 * Provides native implementations for password based encryption related functions.
 */
public final class PBES1 {

    /**
     * Encrypts/Decrypts data using a password. 
     * 
     * @param ockContext The OCKC context to use.
     * @param algorithm The algorithm to be used for encryption.
     * @param password The password to derive a key from which is used to initialize a Cipher.
     * @param salt A salt.
     * @param input The input data.
     * @param iterations The number of iterations to use when deriving the key.
     * @param is_en An indicator to encrypt or decrypt data.
     * @return An array of bytes representing the encrypted/decrypted data.
     * @throws OCKException If input parameters are incorrect or an error occurs in OCKC deriving the key.
     */ 
    public static byte[] PBEdoFinal(OCKContext ockContext, String algorithm, final byte[] password, byte[] salt, 
            final byte[] input, int iterations, int is_en) throws OCKException {
        
        if (ockContext == null) {
            throw new OCKException("Context is null.");
        }

        if (algorithm == null || algorithm.isEmpty()) {
            throw new OCKException("PBE algorithm is null or empty.");
        }

        if (password == null) {
            throw new OCKException("Password is null.");
        }

        if (salt == null || salt.length == 0) {
            throw new OCKException("Salt is null or length 0.");
        }

        if (iterations <= 0) {
            throw new OCKException("Iterations is less then or equal to 0.");
        }

        String text;
        switch (algorithm) {
            case "PBEWithMD5AndDES":
                text = "1.2.840.113549.1.5.3";
                break;
            case "PBEWithSHA1AndDESede":
                text = "1.2.840.113549.1.12.1.3";
                break;
            case "PBEWithSHA1AndRC2_40":
                text = "1.2.840.113549.1.12.1.6";
                break;
            case "PBEWithSHA1AndRC2_128":
                text = "1.2.840.113549.1.12.1.5";
                break;
            case "PBEWithSHA1AndRC4_40":
                text = "1.2.840.113549.1.12.1.2";
                break;
            case "PBEWithSHA1AndRC4_128":
                text = "1.2.840.113549.1.12.1.1";
                break;
            default:
                throw new OCKException("PBE algorithm not supported.");
        }

        byte[] data = NativeInterface.PBE_doFinal(ockContext.getId(), text, password, salt, input, iterations, is_en);

        if (data == null) {
            throw new OCKException("Error encrytping/decrypting data. The return value is null.");
        }

        return data;
    }   
}
