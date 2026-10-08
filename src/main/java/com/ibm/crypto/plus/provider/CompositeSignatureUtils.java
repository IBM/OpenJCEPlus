/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * Fixed-length constants for ML-DSA component fields used in the raw
 * concatenation serialization format defined in
 * draft-ietf-lamps-pq-composite-sigs §4 (Table 1 and the Serialize* routines).
 *
 * <p>All sizes are in bytes and are taken directly from FIPS 204 §7.2.
 */
final class CompositeSignatureUtils {

    // ML-DSA public key lengths (bytes) — FIPS 204 §7.2
    static final int MLDSA44_PK_LEN  = 1312;
    static final int MLDSA65_PK_LEN  = 1952;
    static final int MLDSA87_PK_LEN  = 2592;

    // ML-DSA signature lengths (bytes) — FIPS 204 §7.2
    static final int MLDSA44_SIG_LEN = 2420;
    static final int MLDSA65_SIG_LEN = 3309;
    static final int MLDSA87_SIG_LEN = 4627;

    private CompositeSignatureUtils() {}

    /**
     * Returns the fixed ML-DSA public key length (in bytes) for the given
     * composite algorithm name, based on the ML-DSA parameter set it contains.
     *
     * @param compositeAlg the composite algorithm standard name
     *                     (e.g. {@code "MLDSA65-ECDSA-P256-SHA512"})
     * @return ML-DSA public key length in bytes
     * @throws IllegalArgumentException if the ML-DSA variant cannot be determined
     */
    static int mldsaPublicKeyLen(String compositeAlg) {
        return mldsaParam(compositeAlg, MLDSA44_PK_LEN, MLDSA65_PK_LEN, MLDSA87_PK_LEN);
    }

    /**
     * Returns the fixed ML-DSA signature length (in bytes) for the given
     * composite algorithm name.
     *
     * @param compositeAlg the composite algorithm standard name
     * @return ML-DSA signature length in bytes
     * @throws IllegalArgumentException if the ML-DSA variant cannot be determined
     */
    static int mldsaSignatureLen(String compositeAlg) {
        return mldsaParam(compositeAlg, MLDSA44_SIG_LEN, MLDSA65_SIG_LEN, MLDSA87_SIG_LEN);
    }

    /**
     * Extracts the raw public key bytes from a DER SubjectPublicKeyInfo
     * encoding by reading the BIT STRING payload.
     *
     * @param spki DER-encoded SubjectPublicKeyInfo
     * @return the raw public key bytes (BIT STRING payload, unused-bits removed)
     * @throws java.security.InvalidKeyException if the encoding cannot be parsed
     */
    static byte[] rawPublicKeyFromSpki(byte[] spki)
            throws java.security.InvalidKeyException {
        try {
            sun.security.util.DerValue outer = new sun.security.util.DerValue(spki);
            // Skip AlgorithmIdentifier
            outer.getData().getDerValue();
            // BIT STRING — returns bytes with the leading unused-bits octet stripped
            return outer.getData().getBitString();
        } catch (java.io.IOException e) {
            throw new java.security.InvalidKeyException(
                    "Cannot extract raw public key from SubjectPublicKeyInfo", e);
        }
    }

    /**
     * Extracts the raw private key bytes from a DER OneAsymmetricKey (PKCS#8)
     * encoding by reading the privateKey OCTET STRING payload.
     *
     * @param pkcs8 DER-encoded OneAsymmetricKey
     * @return the raw private key bytes (OCTET STRING payload)
     * @throws java.security.InvalidKeyException if the encoding cannot be parsed
     */
    static byte[] rawPrivateKeyFromPkcs8(byte[] pkcs8)
            throws java.security.InvalidKeyException {
        try {
            sun.security.util.DerValue outer = new sun.security.util.DerValue(pkcs8);
            // version INTEGER
            outer.getData().getInteger();
            // AlgorithmIdentifier SEQUENCE
            outer.getData().getDerValue();
            // privateKey OCTET STRING
            return outer.getData().getOctetString();
        } catch (java.io.IOException e) {
            throw new java.security.InvalidKeyException(
                    "Cannot extract raw private key from OneAsymmetricKey", e);
        }
    }

    /**
     * Selects a value from the three ML-DSA parameter sets based on the
     * composite algorithm name prefix.
     *
     * @param compositeAlg the composite algorithm name
     * @param val44 value for ML-DSA-44
     * @param val65 value for ML-DSA-65
     * @param val87 value for ML-DSA-87
     * @return the selected value
     * @throws IllegalArgumentException if the name does not start with a
     *         recognised ML-DSA variant prefix
     */
    private static int mldsaParam(String compositeAlg, int val44, int val65, int val87) {
        if (compositeAlg == null) {
            throw new IllegalArgumentException("compositeAlg must not be null");
        }
        String up = compositeAlg.toUpperCase(java.util.Locale.ROOT);
        if (up.startsWith("MLDSA44")) {
            return val44;
        }
        if (up.startsWith("MLDSA65")) {
            return val65;
        }
        if (up.startsWith("MLDSA87")) {
            return val87;
        }
        throw new IllegalArgumentException(
                "Cannot determine ML-DSA variant from composite algorithm name: "
                        + compositeAlg);
    }
}
