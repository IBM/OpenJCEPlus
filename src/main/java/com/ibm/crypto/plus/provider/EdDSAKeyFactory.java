/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;

public class EdDSAKeyFactory extends KeyFactorySpi {

    private NamedParameterSpec params = null;
    private OpenJCEPlusProvider provider = null;

    private EdDSAKeyFactory(OpenJCEPlusProvider provider, NamedParameterSpec paramSpec) {
        super();
        this.params = paramSpec;
        this.provider = provider;
    }

    EdDSAKeyFactory(OpenJCEPlusProvider provider) {
        super();
        this.provider = provider;
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {

        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }

        if (key instanceof EdECPublicKey) {
            EdECPublicKey publicKey = (EdECPublicKey) key;
            NamedParameterSpec params = publicKey.getParams();
            checkLockedParams(params);
            if (key instanceof com.ibm.crypto.plus.provider.EdDSAPublicKeyImpl) {
                return key;
            } else {
                return new EdDSAPublicKeyImpl(provider, params, publicKey.getPoint());
            }
        } else if (key instanceof EdECPrivateKey) {
            EdDSAPrivateKeyImpl privKey = null;
            EdECPrivateKey privateKey = (EdECPrivateKey) key;
            NamedParameterSpec params = privateKey.getParams();
            checkLockedParams(params);
            byte[] privateKeyBytes = privateKey.getBytes().get();
            if (privateKeyBytes == null) {
                throw new InvalidKeyException("No private key data");
            }
            if (key instanceof com.ibm.crypto.plus.provider.EdDSAPrivateKeyImpl) {
                privKey = (com.ibm.crypto.plus.provider.EdDSAPrivateKeyImpl) key;
            } else {
                privKey = new EdDSAPrivateKeyImpl(provider, params, Optional.of(privateKeyBytes));
            }
            return privKey;
        } else if (key instanceof PublicKey && key.getFormat().equals("X.509")) {
            EdDSAPublicKeyImpl result = new EdDSAPublicKeyImpl(provider, key.getEncoded());
            checkLockedParams(result.getParams());
            return result;
        } else if (key instanceof PrivateKey && key.getFormat().equals("PKCS#8")) {
            byte[] encoded = key.getEncoded();
            try {
                EdDSAPrivateKeyImpl result = new EdDSAPrivateKeyImpl(provider, encoded);
                checkLockedParams(result.getParams());
                return result;
            } catch (Exception e) {
                throw new InvalidKeyException("Unsupported key type or format");
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } else {
            throw new InvalidKeyException("Unsupported key type or format");
        }
    }

    private void checkLockedParams(NamedParameterSpec spec) throws InvalidKeyException {
        if (this.params != null && !this.params.getName().equals(spec.getName())) {
            throw new InvalidKeyException("Wrong algorithm type");
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {

        try {
            return generatePublicImpl(keySpec);
        } catch (InvalidKeyException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {

        try {
            return generatePrivateImpl(keySpec);
        } catch (InvalidKeyException ex) {
            throw new InvalidKeySpecException(ex);
        }
    }


    private PublicKey generatePublicImpl(KeySpec keySpec)
            throws InvalidKeyException, InvalidKeySpecException {

        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec x509Spec = (X509EncodedKeySpec) keySpec;
            EdDSAPublicKeyImpl result = new EdDSAPublicKeyImpl(provider, x509Spec.getEncoded());
            checkLockedParams(result.getParams());
            return result;
        } else if (keySpec instanceof EdECPublicKeySpec) {
            EdECPublicKeySpec publicKeySpec = (EdECPublicKeySpec) keySpec;
            NamedParameterSpec params = publicKeySpec.getParams();
            checkLockedParams(params);
            return new EdDSAPublicKeyImpl(provider, params, publicKeySpec.getPoint());
        } else {
            throw new InvalidKeySpecException(
                    "Only X509EncodedKeySpec and EdECPublicKeySpec are supported");
        }
    }

    private PrivateKey generatePrivateImpl(KeySpec keySpec)
            throws InvalidKeyException, InvalidKeySpecException {

        if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pkcsSpec = (PKCS8EncodedKeySpec) keySpec;
            byte[] encoded = pkcsSpec.getEncoded();
            try {
                EdDSAPrivateKeyImpl result = new EdDSAPrivateKeyImpl(provider, encoded);
                checkLockedParams(result.getParams());
                return result;
            } catch (Exception e) {
                throw new InvalidKeyException("Unsupported key type or format");
            } finally {
                Arrays.fill(encoded, (byte) 0);
            }
        } else if (keySpec instanceof EdECPrivateKeySpec) {
            EdECPrivateKeySpec privateKeySpec = (EdECPrivateKeySpec) keySpec;
            NamedParameterSpec params = privateKeySpec.getParams();
            checkLockedParams(params);
            byte[] bytes = privateKeySpec.getBytes();
            try {
                return new EdDSAPrivateKeyImpl(provider, params, Optional.of(bytes));
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        } else {
            throw new InvalidKeySpecException(
                    "Only PKCS8EncodedKeySpec and EdECPrivateKeySpec supported");
        }
    }

    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {

        if (key instanceof EdECPublicKey) {
            try {
                checkLockedParams(((EdECPublicKey) key).getParams());
            } catch (InvalidKeyException ex) {
                throw new InvalidKeySpecException(ex);
            }

            if (keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                if (!key.getFormat().equals("X.509")) {
                    throw new InvalidKeySpecException("Format is not X.509");
                }
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else if (keySpec.isAssignableFrom(EdECPublicKeySpec.class)) {
                EdECPublicKey edKey = (EdECPublicKey) key;
                return keySpec.cast(new EdECPublicKeySpec(edKey.getParams(), edKey.getPoint()));
            } else {
                throw new InvalidKeySpecException(
                        "KeySpec must be X509EncodedKeySpec or EdECPublicKeySpec");
            }
        } else if (key instanceof EdECPrivateKey) {
            try {
                checkLockedParams(((EdECPrivateKey) key).getParams());
            } catch (InvalidKeyException ex) {
                throw new InvalidKeySpecException(ex);
            }

            if (keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                if (!key.getFormat().equals("PKCS#8")) {
                    throw new InvalidKeySpecException("Format is not PKCS#8");
                }
                byte[] encoded = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(encoded));
                } finally {
                    Arrays.fill(encoded, (byte) 0);
                }
            } else if (keySpec.isAssignableFrom(EdECPrivateKeySpec.class)) {
                EdECPrivateKey edKey = (EdECPrivateKey) key;
                byte[] scalar = edKey.getBytes()
                        .orElseThrow(() -> new InvalidKeySpecException("No private key value"));
                try {
                    return keySpec.cast(new EdECPrivateKeySpec(edKey.getParams(), scalar));
                } finally {
                    Arrays.fill(scalar, (byte) 0);
                }
            } else {
                throw new InvalidKeySpecException(
                        "KeySpec must be PKCS8EncodedKeySpec or EdECPrivateKeySpec");
            }
        } else {
            throw new InvalidKeySpecException("Unsupported key type");
        }
    }

    public static final class Ed25519 extends EdDSAKeyFactory {

        public Ed25519(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec("Ed25519"));
        }
    }

    public static final class Ed448 extends EdDSAKeyFactory {

        public Ed448(OpenJCEPlusProvider provider) {
            super(provider, new NamedParameterSpec("Ed448"));
        }
    }

    public static final class EdDSA extends EdDSAKeyFactory {

        public EdDSA(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
