/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.XECKey;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import java.util.Optional;

class XDHKeyFactory extends KeyFactorySpi {

    private OpenJCEPlusProvider provider = null;
    private String alg = null;

    static XECKey toXECKey(OpenJCEPlusProvider provider, String Alg, Key key)
            throws InvalidKeyException {
        return (XECKey) new XDHKeyFactory(provider, Alg).engineTranslateKey(key);
    }

    private XDHKeyFactory(OpenJCEPlusProvider provider, String Alg) {
        super();
        this.provider = provider;
        this.alg = Alg;
    }

    private XDHKeyFactory(OpenJCEPlusProvider provider) {
        super();
        this.provider = provider;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof XECPublicKeySpec) {
                XECPublicKeySpec publicKeySpec = (XECPublicKeySpec) keySpec;
                AlgorithmParameterSpec publicKeyParams = publicKeySpec.getParams();
                NamedParameterSpec params = null;
                if (publicKeyParams instanceof NamedParameterSpec) {
                    params = (NamedParameterSpec) publicKeyParams;
                } else {
                    throw new InvalidParameterException("Invalid Parameters: " + publicKeyParams);
                }

                //Validate algs match for key and keyfactory
                if (this.alg != null && !(params.getName().equalsIgnoreCase(this.alg))) {
                    throw new InvalidKeySpecException("Parameters must be " + this.alg);
                }

                BigInteger u = publicKeySpec.getU();
                try {
                    return new XDHPublicKeyImpl(provider, params, u);
                } catch (InvalidAlgorithmParameterException iape) {
                    throw new InvalidKeySpecException(iape);
                }
            } else if (keySpec instanceof X509EncodedKeySpec) {
                return new XDHPublicKeyImpl(provider, ((X509EncodedKeySpec) keySpec).getEncoded());
            } else
                throw new InvalidKeySpecException("Inappropriate key specification");
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        } catch (InvalidParameterException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }

    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            if (keySpec instanceof XECPrivateKeySpec) {
                XECPrivateKeySpec privateKeySpec = (XECPrivateKeySpec) keySpec;
                AlgorithmParameterSpec privateKeyParams = privateKeySpec.getParams();
                NamedParameterSpec params = null;
                if (privateKeyParams instanceof NamedParameterSpec) {
                    params = (NamedParameterSpec) privateKeyParams;
                } else {
                    throw new InvalidParameterException("Invalid Parameters: " + privateKeyParams);
                }

                //Validate algs match for key and keyfactory
                if (this.alg != null && !(params.getName().equalsIgnoreCase(this.alg))) {
                    throw new InvalidKeySpecException("Parameters must be " + this.alg);
                }

                Optional<byte[]> scalar = Optional.of(privateKeySpec.getScalar());
                try {
                    return new XDHPrivateKeyImpl(provider, params, scalar);
                } catch (InvalidAlgorithmParameterException iape) {
                    throw new InvalidKeySpecException(iape);
                }
            } else if (keySpec instanceof PKCS8EncodedKeySpec) {
                return new XDHPrivateKeyImpl(provider,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } else {
                throw new InvalidKeySpecException("Inappropriate key specification");
            }

        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        } catch (InvalidParameterException e) {
            throw new InvalidKeySpecException("Inappropriate key specification: " + e.getMessage());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        AlgorithmParameterSpec params;

        try {
            if (key instanceof XECPublicKey) {
                // Determine valid key specs
                Class<?> xecPubKeySpec = Class.forName("java.security.spec.XECPublicKeySpec");
                Class<?> x509KeySpec = Class.forName("java.security.spec.X509EncodedKeySpec");

                if (keySpec.isAssignableFrom(xecPubKeySpec)) {
                    XECPublicKey xecPubKey = (XECPublicKey) key;
                    params = xecPubKey.getParams();

                    //Validate algs match for key and keyfactory
                    if (this.alg != null && !(((NamedParameterSpec) params)
                            .getName().equalsIgnoreCase(this.alg))) {
                        throw new InvalidKeySpecException("Parameters must be " + this.alg);
                    }

                    BigInteger u = xecPubKey.getU();
                    return keySpec.cast(new XECPublicKeySpec(params, u));
                } else if (keySpec.isAssignableFrom(x509KeySpec))
                    return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
                else
                    throw new InvalidKeySpecException("Inappropriate key specification");

            } else if (key instanceof XECPrivateKey) {

                // Determine valid key specs
                Class<?> xecPrivKeySpec = Class.forName("java.security.spec.XECPrivateKeySpec");
                Class<?> pkcs8KeySpec = Class.forName("java.security.spec.PKCS8EncodedKeySpec");

                if (keySpec.isAssignableFrom(xecPrivKeySpec)) {
                    XECPrivateKey xecPrivKey = (XECPrivateKey) key;
                    params = xecPrivKey.getParams();

                    //Validate algs match for key and keyfactory
                    if (this.alg != null && !(((NamedParameterSpec) params)
                            .getName().equalsIgnoreCase(this.alg))) {
                        throw new InvalidKeySpecException("Parameters must be " + this.alg);
                    }

                    Optional<byte[]> scalar = xecPrivKey.getScalar();
                    byte[] scalarArray = scalar.get();
                    try {
                        return keySpec.cast(new XECPrivateKeySpec(params, scalarArray));
                    } finally {
                        Arrays.fill(scalarArray, (byte) 0x00);
                    }
                } else if (keySpec.isAssignableFrom(pkcs8KeySpec))
                    return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
                else
                    throw new InvalidKeySpecException("Inappropriate key specification");
            } else
                throw new InvalidKeySpecException("Inappropriate key type");
        } catch (ClassNotFoundException e) {
            throw new InvalidKeySpecException("Unsupported key specification: " + e.getMessage());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        try {

            if (key instanceof XECPublicKey) {
                //Validate algs match for key and keyfactory
                if (this.alg != null
                        && !(((NamedParameterSpec) ((XECPublicKey) key)
                                .getParams()).getName().equalsIgnoreCase(this.alg))) {
                    throw new InvalidKeyException("Parameters must be " + this.alg);
                }

                // Check if key originates from this factory
                if (key instanceof XDHPublicKeyImpl)
                    return key;

                // Convert key to spec
                XECPublicKeySpec xecPubKeySpec = engineGetKeySpec(key,
                        XECPublicKeySpec.class);

                // Create key from spec, and return it
                return engineGeneratePublic(xecPubKeySpec);

            } else if (key instanceof XECPrivateKey) {
                //Validate algs match for key and keyfactory
                if (this.alg != null
                        && !(((NamedParameterSpec) ((XECPrivateKey) key)
                                .getParams()).getName().equalsIgnoreCase(this.alg))) {
                    throw new InvalidKeyException("Parameters must be " + this.alg);
                }

                // Check if key originates from this factory
                if (key instanceof XDHPrivateKeyImpl)
                    return key;

                // Convert key to spec
                XECPrivateKeySpec xecPrivKeySpec = engineGetKeySpec(key,
                        XECPrivateKeySpec.class);
                // Create key from spec, and return it
                return engineGeneratePrivate(xecPrivKeySpec);

            } else
                throw new InvalidKeyException("Wrong algorithm type");

        } catch (InvalidKeySpecException e) {
            throw new InvalidKeyException("Cannot translate key: " + e.getMessage());
        }
    }

    public static final class X25519 extends XDHKeyFactory {
        public X25519(OpenJCEPlusProvider provider) {
            super(provider, "X25519");
        }
    }

    public static final class X448 extends XDHKeyFactory {
        public X448(OpenJCEPlusProvider provider) {
            super(provider, "X448");
        }
    }

    public static final class XDH extends XDHKeyFactory {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
