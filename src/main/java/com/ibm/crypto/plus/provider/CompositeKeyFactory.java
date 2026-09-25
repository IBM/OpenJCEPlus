/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyFactory for composite signature algorithms defined in
 * draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Supported KeySpec types:
 * <ul>
 *   <li>{@link X509EncodedKeySpec} → {@link CompositePublicKey}
 *   <li>{@link PKCS8EncodedKeySpec} → {@link CompositePrivateKey}
 * </ul>
 */
class CompositeKeyFactory extends KeyFactorySpi {

    private final OpenJCEPlusProvider provider;
    private final String algName;

    CompositeKeyFactory(OpenJCEPlusProvider provider, String algName) {
        this.provider = provider;
        this.algName = algName;
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof X509EncodedKeySpec) {
            try {
                return new CompositePublicKey(algName,
                        ((X509EncodedKeySpec) keySpec).getEncoded());
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(
                        "Cannot generate composite public key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported KeySpec: "
                + keySpec.getClass().getName()
                + "; only X509EncodedKeySpec is supported");
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            try {
                return new CompositePrivateKey(algName,
                        ((PKCS8EncodedKeySpec) keySpec).getEncoded());
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(
                        "Cannot generate composite private key", e);
            }
        }
        throw new InvalidKeySpecException("Unsupported KeySpec: "
                + keySpec.getClass().getName()
                + "; only PKCS8EncodedKeySpec is supported");
    }

    @Override
    @SuppressWarnings("unchecked")
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key instanceof CompositePublicKey) {
            if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            }
            throw new InvalidKeySpecException(
                    "Only X509EncodedKeySpec supported for composite public key");
        }
        if (key instanceof CompositePrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            }
            throw new InvalidKeySpecException(
                    "Only PKCS8EncodedKeySpec supported for composite private key");
        }
        throw new InvalidKeySpecException("Unsupported key type: "
                + key.getClass().getName());
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (key instanceof CompositePublicKey) {
            return key;
        }
        if (key instanceof CompositePrivateKey) {
            return key;
        }
        // Try to convert via encoded form
        if (key instanceof PublicKey) {
            try {
                return engineGeneratePublic(
                        new X509EncodedKeySpec(key.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Cannot translate public key", e);
            }
        }
        if (key instanceof PrivateKey) {
            try {
                return engineGeneratePrivate(
                        new PKCS8EncodedKeySpec(key.getEncoded()));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException("Cannot translate private key", e);
            }
        }
        throw new InvalidKeyException("Unsupported key type: "
                + key.getClass().getName());
    }

    // -----------------------------------------------------------------------
    // Unused — needed to satisfy the abstract method for resolving the
    // algorithm when called via KeyFactory.getInstance(algo, provider).
    // -----------------------------------------------------------------------

    /**
     * Returns a {@link CompositeKeyFactory} for the given composite algorithm
     * name by delegating to the provider's standard service lookup.
     */
    static Key toCompositeKey(OpenJCEPlusProvider provider, Key key)
            throws InvalidKeyException {
        try {
            KeyFactory kf = KeyFactory.getInstance(key.getAlgorithm(), provider);
            return kf.translateKey(key);
        } catch (Exception e) {
            throw new InvalidKeyException(
                    "Cannot translate key to composite key", e);
        }
    }

    // -----------------------------------------------------------------------
    // Concrete inner classes — one per composite algorithm combination
    // -----------------------------------------------------------------------

    public static final class MLDSA44RSA2048PSSSHA256 extends CompositeKeyFactory {
        public MLDSA44RSA2048PSSSHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PSS-SHA256");
        }
    }

    public static final class MLDSA44RSA2048PKCS15SHA256 extends CompositeKeyFactory {
        public MLDSA44RSA2048PKCS15SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PKCS15-SHA256");
        }
    }

    public static final class MLDSA44Ed25519 extends CompositeKeyFactory {
        public MLDSA44Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-Ed25519");
        }
    }

    public static final class MLDSA44ECDSAP256SHA256 extends CompositeKeyFactory {
        public MLDSA44ECDSAP256SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-ECDSA-P256-SHA256");
        }
    }

    public static final class MLDSA65RSA3072PSSSHA512 extends CompositeKeyFactory {
        public MLDSA65RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PSS-SHA512");
        }
    }

    public static final class MLDSA65RSA3072PKCS15SHA512 extends CompositeKeyFactory {
        public MLDSA65RSA3072PKCS15SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PKCS15-SHA512");
        }
    }

    public static final class MLDSA65RSA4096PSSSHA512 extends CompositeKeyFactory {
        public MLDSA65RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA4096-PSS-SHA512");
        }
    }

    public static final class MLDSA65RSA4096PKCS15SHA512 extends CompositeKeyFactory {
        public MLDSA65RSA4096PKCS15SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA4096-PKCS15-SHA512");
        }
    }

    public static final class MLDSA65ECDSAP256SHA512 extends CompositeKeyFactory {
        public MLDSA65ECDSAP256SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P256-SHA512");
        }
    }

    public static final class MLDSA65ECDSAP384SHA512 extends CompositeKeyFactory {
        public MLDSA65ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P384-SHA512");
        }
    }

    public static final class MLDSA65ECDSABrainpoolP256r1SHA512 extends CompositeKeyFactory {
        public MLDSA65ECDSABrainpoolP256r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-brainpoolP256r1-SHA512");
        }
    }

    public static final class MLDSA65Ed25519 extends CompositeKeyFactory {
        public MLDSA65Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-Ed25519");
        }
    }

    public static final class MLDSA87ECDSAP384SHA512 extends CompositeKeyFactory {
        public MLDSA87ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P384-SHA512");
        }
    }

    public static final class MLDSA87ECDSABrainpoolP384r1SHA512 extends CompositeKeyFactory {
        public MLDSA87ECDSABrainpoolP384r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-brainpoolP384r1-SHA512");
        }
    }

    public static final class MLDSA87Ed448 extends CompositeKeyFactory {
        public MLDSA87Ed448(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-Ed448");
        }
    }

    public static final class MLDSA87RSA3072PSSSHA512 extends CompositeKeyFactory {
        public MLDSA87RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-RSA3072-PSS-SHA512");
        }
    }

    public static final class MLDSA87RSA4096PSSSHA512 extends CompositeKeyFactory {
        public MLDSA87RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-RSA4096-PSS-SHA512");
        }
    }

    public static final class MLDSA87ECDSAP521SHA512 extends CompositeKeyFactory {
        public MLDSA87ECDSAP521SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P521-SHA512");
        }
    }
}
