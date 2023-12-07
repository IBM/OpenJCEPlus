/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

final class ConstructKeys {

    /**
     * Construct a public key from its encoding.
     *
     * @param encodedKey
     *            the encoding of a public key.
     *
     * @param encodedKeyAlgorithm
     *            the algorithm the encodedKey is for.
     *
     * @return a public key constructed from the encodedKey.
     */
    static final PublicKey constructPublicKey(OpenJCEPlusProvider provider, byte[] encodedKey,
            String encodedKeyAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        PublicKey key = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm, provider);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
            key = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            // Try to see whether there is another
            // provider which supports this algorithm
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
                key = keyFactory.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException nsae2) {
                throw new NoSuchAlgorithmException("No installed providers "
                        + "can create keys for the " + encodedKeyAlgorithm + "algorithm");
            } catch (InvalidKeySpecException ikse2) {
                // Should never happen.
            }
        } catch (InvalidKeySpecException ikse) {
            // Should never happen.
        }

        return key;
    }

    /**
     * Construct a private key from its encoding.
     *
     * @param encodedKey
     *            the encoding of a private key.
     *
     * @param encodedKeyAlgorithm
     *            the algorithm the wrapped key is for.
     *
     * @return a private key constructed from the encodedKey.
     */
    static final PrivateKey constructPrivateKey(OpenJCEPlusProvider provider, byte[] encodedKey,
            String encodedKeyAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException {
        PrivateKey key = null;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm, provider);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
            return keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException nsae) {
            // Try to see whether there is another
            // provider which supports this algorithm
            try {
                KeyFactory keyFactory = KeyFactory.getInstance(encodedKeyAlgorithm);
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
                key = keyFactory.generatePrivate(keySpec);
            } catch (NoSuchAlgorithmException nsae2) {
                throw new NoSuchAlgorithmException("No installed providers "
                        + "can create keys for the " + encodedKeyAlgorithm + "algorithm");
            } catch (InvalidKeySpecException ikse2) {
                // Should never happen.
            }
        } catch (InvalidKeySpecException ikse) {
            // Should never happen.
        }

        return key;
    }

    /**
     * Construct a secret key from its encoding.
     *
     * @param encodedKey
     *            the encoding of a secret key.
     *
     * @param encodedKeyAlgorithm
     *            the algorithm the secret key is for.
     *
     * @return a secret key constructed from the encodedKey.
     */
    static final SecretKey constructSecretKey(OpenJCEPlusProvider provider, byte[] encodedKey,
            String encodedKeyAlgorithm) {
        return (new SecretKeySpec(encodedKey, encodedKeyAlgorithm));
    }

    static final Key constructKey(OpenJCEPlusProvider provider, byte[] encoding,
            String keyAlgorithm, int keyType) throws InvalidKeyException, NoSuchAlgorithmException {
        Key result = null;
        switch (keyType) {
            case Cipher.SECRET_KEY:
                result = ConstructKeys.constructSecretKey(provider, encoding, keyAlgorithm);
                break;
            case Cipher.PRIVATE_KEY:
                result = ConstructKeys.constructPrivateKey(provider, encoding, keyAlgorithm);
                break;
            case Cipher.PUBLIC_KEY:
                result = ConstructKeys.constructPublicKey(provider, encoding, keyAlgorithm);
                break;
        }
        return result;
    }
}
