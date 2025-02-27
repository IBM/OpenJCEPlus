/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class implements the ChaCha20 key factory.
 */
public final class ChaCha20KeyFactory extends SecretKeyFactorySpi {

    private OpenJCEPlusProvider provider = null;

    /**
     * Empty constructor
     */
    public ChaCha20KeyFactory(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
        this.provider = provider;
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material).
     *
     * @param keySpec
     *            the specification (key material) of the secret key
     *
     * @return the secret key
     *
     * @exception InvalidKeySpecException
     *                if the given key specification is inappropriate for this
     *                key factory to produce a secret key.
     */
    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof SecretKeySpec) {
                return new ChaCha20Key(((SecretKeySpec) keySpec).getEncoded());
            }
            throw new InvalidKeySpecException("Inappropriate key specification");
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e.getMessage());
        }
    }

    /**
     * Returns a specification (key material) of the given key in the requested
     * format.
     *
     * @param key
     *            the key
     *
     * @param keySpec
     *            the requested format in which the key material shall be
     *            returned
     *
     * @return the underlying key specification (key material) in the requested
     *         format
     *
     * @exception InvalidKeySpecException
     *                if the requested key specification is inappropriate for
     *                the given key, or the given key cannot be processed (e.g.,
     *                the given key has an unrecognized algorithm or format).
     */
    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec)
            throws InvalidKeySpecException {
        // try {
        if ((key instanceof SecretKey) && (key.getAlgorithm().equalsIgnoreCase("ChaCha20"))
                && (key.getFormat().equalsIgnoreCase("RAW"))) {

            // Check if requested key spec is amongst the valid ones
            if (keySpec.isAssignableFrom(SecretKeySpec.class)) {
                return new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } else {
            throw new InvalidKeySpecException("Inappropriate key format/algorithm");
        }
    }

    /**
     * Translates a <code>SecretKey</code> object, whose provider may be unknown
     * or potentially untrusted, into a corresponding <code>SecretKey</code>
     * object of this key factory.
     *
     * @param key
     *            the key whose provider is unknown or untrusted
     *
     * @return the translated key
     *
     * @exception InvalidKeyException
     *                if the given key cannot be processed by this key factory.
     */
    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        try {
            if ((key != null) && (key.getAlgorithm().equalsIgnoreCase("ChaCha20"))
                    && (key.getFormat().equalsIgnoreCase("RAW"))) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.ChaCha20Key) {
                    return key;
                }

                // Convert key to spec
                SecretKeySpec secretKeySpec = (SecretKeySpec) engineGetKeySpec(key,
                        SecretKeySpec.class);

                // Create key from spec, and return it
                return engineGenerateSecret(secretKeySpec);
            } else {
                throw new InvalidKeyException("Inappropriate key format/algorithm");
            }

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key");
        }
    }
}
