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
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class DSAKeyFactory extends KeyFactorySpi {

    public final static int MIN_PRIME_SIZE_NONFIPS = 512;
    public final static int MIN_PRIME_SIZE_FIPS = 2048;

    private OpenJCEPlusProvider provider;

    static DSAKey toDSAKey(OpenJCEPlusProvider provider, Key key) throws InvalidKeyException {
        return (DSAKey) new DSAKeyFactory(provider).engineTranslateKey(key);
    }

    public DSAKeyFactory(OpenJCEPlusProvider provider) {
        super();
        this.provider = provider;
    }

    static int getDefaultSubprimeLen(int modlen) {
        int subPrimeLen = -1;
        if (modlen <= 1024) {
            subPrimeLen = 160;
        } else if (modlen == 2048) {
            subPrimeLen = 224;
        } else if (modlen == 3072) {
            subPrimeLen = 256;
        }
        return subPrimeLen;
    }

    static void checkStrength(OpenJCEPlusProvider provider, int sizeP, int sizeQ)
            throws InvalidKeyException {

        int minSizeP = provider.isFIPS() ? MIN_PRIME_SIZE_FIPS : MIN_PRIME_SIZE_NONFIPS;
        if (sizeP < minSizeP) {
            throw new InvalidKeyException("Prime size must be at least " + minSizeP);
        }

        //Check for valid prime and subprime combinations.
        if (!(((sizeP >= 512 && sizeP <= 1024 && sizeP % 64 == 0 && sizeQ == 160)
                || (sizeP == 2048 && (sizeQ == 224 || sizeQ == 256))
                || (sizeP == 3072 && sizeQ == 256)))) {
            throw new InvalidKeyException(
                    "Unsupported prime and subprime size combination: " + sizeP + ", " + sizeQ);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof DSAPublicKeySpec) {
                DSAPublicKeySpec publicKeySpec = (DSAPublicKeySpec) keySpec;
                BigInteger p = publicKeySpec.getP();
                BigInteger q = publicKeySpec.getQ();
                BigInteger g = publicKeySpec.getG();
                BigInteger y = publicKeySpec.getY();
                return new DSAPublicKey(provider, y, p, q, g);
            } else if (keySpec instanceof X509EncodedKeySpec) {
                return new DSAPublicKey(provider, ((X509EncodedKeySpec) keySpec).getEncoded());
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }
        } catch (InvalidKeyException e) {

            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof DSAPrivateKeySpec) {
                DSAPrivateKeySpec privateKeySpec = (DSAPrivateKeySpec) keySpec;
                BigInteger p = privateKeySpec.getP();
                BigInteger q = privateKeySpec.getQ();
                BigInteger g = privateKeySpec.getG();
                BigInteger x = privateKeySpec.getX();
                return new DSAPrivateKey(provider, x, p, q, g);
            } else if (keySpec instanceof PKCS8EncodedKeySpec) {
                return new DSAPrivateKey(provider, ((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        DSAParams params;

        try {
            if (key instanceof java.security.interfaces.DSAPublicKey) {
                // Determine valid key specs
                Class<?> dsaPubKeySpec = Class.forName("java.security.spec.DSAPublicKeySpec");
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");

                if (keySpec.isAssignableFrom(dsaPubKeySpec)) {
                    java.security.interfaces.DSAPublicKey dsaPubKey = (java.security.interfaces.DSAPublicKey) key;
                    params = dsaPubKey.getParams();
                    return keySpec.cast(new DSAPublicKeySpec(dsaPubKey.getY(), params.getP(),
                            params.getQ(), params.getG()));

                } else if (keySpec.isAssignableFrom(x509KeySpec)) {
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));

                } else {
                    throw new InvalidKeySpecException("Inappropriate key specification");
                }

            } else if (key instanceof java.security.interfaces.DSAPrivateKey) {

                // Determine valid key specs
                Class<?> dsaPrivKeySpec = Class.forName("java.security.spec.DSAPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");

                if (keySpec.isAssignableFrom(dsaPrivKeySpec)) {
                    java.security.interfaces.DSAPrivateKey dsaPrivKey = (java.security.interfaces.DSAPrivateKey) key;
                    params = dsaPrivKey.getParams();
                    return keySpec.cast(new DSAPrivateKeySpec(dsaPrivKey.getX(), params.getP(),
                            params.getQ(), params.getG()));

                } else if (keySpec.isAssignableFrom(pkcs8KeySpec)) {
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

            if (key instanceof java.security.interfaces.DSAPublicKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.DSAPublicKey) {
                    return key;
                }
                // Convert key to spec
                DSAPublicKeySpec dsaPubKeySpec = engineGetKeySpec(key,
                        DSAPublicKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePublic(dsaPubKeySpec);

            } else if (key instanceof java.security.interfaces.DSAPrivateKey) {
                // Check if key originates from this factory
                if (key instanceof com.ibm.crypto.plus.provider.DSAPrivateKey) {
                    return key;
                }
                // Convert key to spec
                DSAPrivateKeySpec dsaPrivKeySpec = engineGetKeySpec(key,
                        DSAPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(dsaPrivKeySpec);

            } else {
                throw new InvalidKeyException("Wrong algorithm type");
            }

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }
}
