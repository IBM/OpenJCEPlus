/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

/**
 * KeyPairGenerator for composite signature algorithms defined in
 * draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Each concrete inner class generates both a ML-DSA component key pair and
 * a traditional component key pair, then wraps them into a
 * {@link CompositePublicKey} / {@link CompositePrivateKey} pair.
 */
abstract class CompositeKeyPairGenerator extends KeyPairGeneratorSpi {

    private final OpenJCEPlusProvider provider;
    /** Standard name of the composite algorithm (e.g. {@code "MLDSA44-ECDSA-P256-SHA256"}). */
    private final String compositeAlg;
    /** Standard name of the ML-DSA component (e.g. {@code "ML-DSA-44"}). */
    private final String mldsaAlg;
    /** JCA algorithm name used to create the traditional KeyPairGenerator. */
    private final String tradKpgAlg;
    /**
     * Optional EC curve name passed to {@code ECGenParameterSpec}; {@code null}
     * for RSA and EdDSA algorithms where size/params are fixed.
     */
    private final String ecCurveName;
    /**
     * RSA key size; only meaningful when {@code ecCurveName} is {@code null}
     * and the traditional component is RSA.
     */
    private final int rsaKeySize;

    CompositeKeyPairGenerator(OpenJCEPlusProvider provider, String compositeAlg,
            String mldsaAlg, String tradKpgAlg, String ecCurveName, int rsaKeySize) {
        this.provider = provider;
        this.compositeAlg = compositeAlg;
        this.mldsaAlg = mldsaAlg;
        this.tradKpgAlg = tradKpgAlg;
        this.ecCurveName = ecCurveName;
        this.rsaKeySize = rsaKeySize;
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        throw new InvalidParameterException(
                "Key size is fixed for composite algorithm " + compositeAlg);
    }

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "No parameters accepted for composite algorithm " + compositeAlg);
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            // --- Generate ML-DSA component key pair ---
            KeyPairGenerator mldsaKpg =
                    KeyPairGenerator.getInstance(mldsaAlg, provider);
            KeyPair mldsaKp = mldsaKpg.generateKeyPair();

            // --- Generate traditional component key pair ---
            KeyPairGenerator tradKpg =
                    KeyPairGenerator.getInstance(tradKpgAlg, provider);
            if (ecCurveName != null) {
                // EC or EdDSA: initialize with named curve
                tradKpg.initialize(new ECGenParameterSpec(ecCurveName));
            } else if (rsaKeySize > 0) {
                tradKpg.initialize(rsaKeySize);
            }
            // Ed25519 / Ed448 need no further initialization
            KeyPair tradKp = tradKpg.generateKeyPair();

            CompositePublicKey pubKey = new CompositePublicKey(
                    compositeAlg,
                    mldsaKp.getPublic().getEncoded(),
                    tradKp.getPublic().getEncoded());

            CompositePrivateKey privKey = new CompositePrivateKey(
                    compositeAlg,
                    mldsaKp.getPrivate().getEncoded(),
                    tradKp.getPrivate().getEncoded());

            return new KeyPair(pubKey, privKey);
        } catch (Exception e) {
            throw provider.providerException(
                    "Failure in CompositeKeyPairGenerator.generateKeyPair", e);
        }
    }

    // -----------------------------------------------------------------------
    // Concrete inner classes — one per composite algorithm combination
    // -----------------------------------------------------------------------

    public static final class MLDSA44RSA2048PSSSHA256 extends CompositeKeyPairGenerator {
        public MLDSA44RSA2048PSSSHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PSS-SHA256", "ML-DSA-44", "RSA", null, 2048);
        }
    }

    public static final class MLDSA44RSA2048PKCS15SHA256 extends CompositeKeyPairGenerator {
        public MLDSA44RSA2048PKCS15SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-RSA2048-PKCS15-SHA256", "ML-DSA-44", "RSA", null, 2048);
        }
    }

    public static final class MLDSA44Ed25519 extends CompositeKeyPairGenerator {
        public MLDSA44Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-Ed25519", "ML-DSA-44", "Ed25519", null, 0);
        }
    }

    public static final class MLDSA44ECDSAP256SHA256 extends CompositeKeyPairGenerator {
        public MLDSA44ECDSAP256SHA256(OpenJCEPlusProvider p) {
            super(p, "MLDSA44-ECDSA-P256-SHA256", "ML-DSA-44", "EC", "secp256r1", 0);
        }
    }

    public static final class MLDSA65RSA3072PSSSHA512 extends CompositeKeyPairGenerator {
        public MLDSA65RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PSS-SHA512", "ML-DSA-65", "RSA", null, 3072);
        }
    }

    public static final class MLDSA65RSA3072PKCS15SHA512 extends CompositeKeyPairGenerator {
        public MLDSA65RSA3072PKCS15SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA3072-PKCS15-SHA512", "ML-DSA-65", "RSA", null, 3072);
        }
    }

    public static final class MLDSA65RSA4096PSSSHA512 extends CompositeKeyPairGenerator {
        public MLDSA65RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA4096-PSS-SHA512", "ML-DSA-65", "RSA", null, 4096);
        }
    }

    public static final class MLDSA65RSA4096PKCS15SHA512 extends CompositeKeyPairGenerator {
        public MLDSA65RSA4096PKCS15SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-RSA4096-PKCS15-SHA512", "ML-DSA-65", "RSA", null, 4096);
        }
    }

    public static final class MLDSA65ECDSAP256SHA512 extends CompositeKeyPairGenerator {
        public MLDSA65ECDSAP256SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P256-SHA512", "ML-DSA-65", "EC", "secp256r1", 0);
        }
    }

    public static final class MLDSA65ECDSAP384SHA512 extends CompositeKeyPairGenerator {
        public MLDSA65ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-P384-SHA512", "ML-DSA-65", "EC", "secp384r1", 0);
        }
    }

    public static final class MLDSA65ECDSABrainpoolP256r1SHA512 extends CompositeKeyPairGenerator {
        public MLDSA65ECDSABrainpoolP256r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-ECDSA-brainpoolP256r1-SHA512", "ML-DSA-65",
                    "EC", "brainpoolP256r1", 0);
        }
    }

    public static final class MLDSA65Ed25519 extends CompositeKeyPairGenerator {
        public MLDSA65Ed25519(OpenJCEPlusProvider p) {
            super(p, "MLDSA65-Ed25519", "ML-DSA-65", "Ed25519", null, 0);
        }
    }

    public static final class MLDSA87ECDSAP384SHA512 extends CompositeKeyPairGenerator {
        public MLDSA87ECDSAP384SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P384-SHA512", "ML-DSA-87", "EC", "secp384r1", 0);
        }
    }

    public static final class MLDSA87ECDSABrainpoolP384r1SHA512 extends CompositeKeyPairGenerator {
        public MLDSA87ECDSABrainpoolP384r1SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-brainpoolP384r1-SHA512", "ML-DSA-87",
                    "EC", "brainpoolP384r1", 0);
        }
    }

    public static final class MLDSA87Ed448 extends CompositeKeyPairGenerator {
        public MLDSA87Ed448(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-Ed448", "ML-DSA-87", "Ed448", null, 0);
        }
    }

    public static final class MLDSA87RSA3072PSSSHA512 extends CompositeKeyPairGenerator {
        public MLDSA87RSA3072PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-RSA3072-PSS-SHA512", "ML-DSA-87", "RSA", null, 3072);
        }
    }

    public static final class MLDSA87RSA4096PSSSHA512 extends CompositeKeyPairGenerator {
        public MLDSA87RSA4096PSSSHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-RSA4096-PSS-SHA512", "ML-DSA-87", "RSA", null, 4096);
        }
    }

    public static final class MLDSA87ECDSAP521SHA512 extends CompositeKeyPairGenerator {
        public MLDSA87ECDSAP521SHA512(OpenJCEPlusProvider p) {
            super(p, "MLDSA87-ECDSA-P521-SHA512", "ML-DSA-87", "EC", "secp521r1", 0);
        }
    }
}
