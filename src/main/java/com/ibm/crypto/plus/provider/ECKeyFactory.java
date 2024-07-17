/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class ECKeyFactory extends KeyFactorySpi {

    private OpenJCEPlusProvider provider = null;

    static ECKey toECKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        return (ECKey) new ECKeyFactory(provider).engineTranslateKey(key);
    }

    public ECKeyFactory(OpenJCEPlusProvider provider) {
        super();

        this.provider = provider;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof ECPublicKeySpec) {
                ECPublicKeySpec publicKeySpec = (ECPublicKeySpec) keySpec;
                ECPoint w = publicKeySpec.getW();
                ECParameterSpec ecParams = publicKeySpec.getParams();
                return new ECPublicKey(provider, w, ecParams);
            } else if (keySpec instanceof X509EncodedKeySpec) {
                return new ECPublicKey(provider, ((X509EncodedKeySpec) keySpec).getEncoded());
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {

            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeySpecException(
                    "Inappropriate parameter specification: " + e.getMessage());
        }

    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        // System.out.println ("In EngingeGeneratePrivate");
        try {
            if (keySpec instanceof ECPrivateKeySpec) {
                ECPrivateKeySpec privateKeySpec = (ECPrivateKeySpec) keySpec;
                BigInteger s = privateKeySpec.getS();
                ECParameterSpec ecParams = privateKeySpec.getParams();
                return new ECPrivateKey(provider, s, ecParams);
            } else if (keySpec instanceof PKCS8EncodedKeySpec) {
                // System.out.println ("PKCS8EncodedKeySpec");
                byte[] encodedPrivKeySpec = ((PKCS8EncodedKeySpec) keySpec).getEncoded();
                // System.out.println ("encodedPrivKeySpec=" +
                // ECUtils.bytesToHex(encodedPrivKeySpec));
                return new ECPrivateKey(provider, encodedPrivKeySpec);
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        } catch (InvalidParameterSpecException e) {
            throw new InvalidKeySpecException(
                    "Inappropriate Parameter specification: " + e.getMessage());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {

        try {
            if (key instanceof java.security.interfaces.ECPublicKey) {
                // Determine valid key specs
                Class<?> ecPubKeySpec = Class.forName("java.security.spec.ECPublicKeySpec");
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");

                if (ecPubKeySpec.isAssignableFrom(keySpec)) {
                    java.security.interfaces.ECPublicKey ecPubKey = (java.security.interfaces.ECPublicKey) key;

                    return keySpec.cast(new ECPublicKeySpec(ecPubKey.getW(), ecPubKey.getParams()));

                } else if (x509KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));

                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }

            } else if (key instanceof java.security.interfaces.ECPrivateKey) {

                // Determine valid key specs
                Class<?> ecPrivKeySpec = Class.forName("java.security.spec.ECPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");

                if (ecPrivKeySpec.isAssignableFrom(keySpec)) {
                    java.security.interfaces.ECPrivateKey ecPrivKey = (java.security.interfaces.ECPrivateKey) key;
                    return keySpec
                            .cast(new ECPrivateKeySpec(ecPrivKey.getS(), ecPrivKey.getParams()));

                } else if (pkcs8KeySpec.isAssignableFrom(keySpec)) {
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));

                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }

            } else {
                throw new InvalidKeySpecException("Inappropriate key type");
            }

        } catch (ClassNotFoundException e) {
            throw new InvalidKeySpecException("Unsupported key specification: " + e.getMessage());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        try {

            if (key instanceof java.security.interfaces.ECPublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.ECPublicKey) {
                    return key;
                }
                // Convert key to spec
                ECPublicKeySpec ecPubKeySpec = engineGetKeySpec(key,
                        ECPublicKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(ecPubKeySpec);

            } else if (key instanceof java.security.interfaces.ECPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.ECPrivateKey) {
                    return key;
                }
                // Convert key to spec
                ECPrivateKeySpec ecPrivKeySpec = engineGetKeySpec(key,
                        ECPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(ecPrivKeySpec);

            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }

}
