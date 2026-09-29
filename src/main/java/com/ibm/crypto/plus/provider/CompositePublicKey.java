/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * Composite public key as defined in draft-ietf-lamps-pq-composite-sigs §5.
 *
 * <p>The key is encoded as a SubjectPublicKeyInfo (SPKI) whose subjectPublicKey
 * BIT STRING payload is the raw concatenation of the two component public keys
 * per §4.1 (SerializePublicKey):
 *
 * <pre>
 * subjectPublicKey BIT STRING payload = mldsaPK || tradPK
 * </pre>
 *
 * <p>The ML-DSA component public key ({@code mldsaRaw}) is the fixed-length raw
 * public key bytes as specified in FIPS 204 §7.2 (1312, 1952, or 2592 bytes for
 * ML-DSA-44, -65, -87 respectively). The traditional component public key
 * ({@code tradRaw}) is the raw public key bytes appropriate to its algorithm
 * (uncompressed X9.62 EC point, RSAPublicKey DER, or raw EdDSA key bytes).
 *
 * <p>The first component is always ML-DSA; the second is the traditional
 * component.
 */
@SuppressWarnings("restriction")
final class CompositePublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    /** Raw ML-DSA public key bytes (fixed length per FIPS 204 §7.2). */
    private final byte[] mldsaRaw;
    /** Raw traditional component public key bytes. */
    private final byte[] tradRaw;
    /** Cached outer SubjectPublicKeyInfo encoding (lazy). */
    private volatile byte[] encoded;
    private transient boolean destroyed = false;

    /**
     * Constructs a composite public key from the two raw component public key
     * byte arrays.
     *
     * @param algorithm the composite algorithm name (e.g.
     *                  {@code "MLDSA44-ECDSA-P256-SHA256"})
     * @param mldsaRaw  raw ML-DSA public key bytes (1312, 1952, or 2592 bytes)
     * @param tradRaw   raw traditional component public key bytes
     */
    CompositePublicKey(String algorithm, byte[] mldsaRaw, byte[] tradRaw) {
        this.algorithm = algorithm;
        this.mldsaRaw = mldsaRaw.clone();
        this.tradRaw = tradRaw.clone();
    }

    /**
     * Constructs a composite public key by parsing an outer SubjectPublicKeyInfo
     * encoding whose BIT STRING payload is {@code mldsaPK || tradPK} per §4.1.
     *
     * @param algorithm the composite algorithm name
     * @param encoded   the outer SubjectPublicKeyInfo encoding
     * @throws InvalidKeyException if the encoding cannot be parsed
     */
    CompositePublicKey(String algorithm, byte[] encoded) throws InvalidKeyException {
        this.algorithm = algorithm;
        try {
            // Parse outer SubjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }
            DerValue outer = new DerValue(encoded);
            if (outer.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Not a SEQUENCE");
            }
            // Skip AlgorithmIdentifier
            outer.getData().getDerValue();
            // BIT STRING payload = mldsaPK || tradPK (raw concatenation per §4.1)
            byte[] payload = outer.getData().getBitString();

            int mldsaLen = CompositeSignatureUtils.mldsaPublicKeyLen(algorithm);
            if (payload.length < mldsaLen) {
                throw new InvalidKeyException(
                        "Composite public key payload too short: " + payload.length
                                + " < " + mldsaLen);
            }
            this.mldsaRaw = java.util.Arrays.copyOfRange(payload, 0, mldsaLen);
            this.tradRaw  = java.util.Arrays.copyOfRange(payload, mldsaLen, payload.length);
            this.encoded = encoded.clone();
        } catch (IOException e) {
            throw new InvalidKeyException("Failed to decode composite public key", e);
        }
    }

    /** Returns the raw ML-DSA public key bytes. */
    byte[] getMLDSARaw() {
        checkDestroyed();
        return mldsaRaw.clone();
    }

    /** Returns the raw traditional component public key bytes. */
    byte[] getTradRaw() {
        checkDestroyed();
        return tradRaw.clone();
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return algorithm;
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return "X.509";
    }

    /**
     * Returns the SubjectPublicKeyInfo (X.509) encoding of this composite key.
     *
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm  AlgorithmIdentifier,
     *     publicKey  BIT STRING  -- payload: mldsaPK || tradPK (raw, §4.1)
     * }
     * </pre>
     */
    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        if (encoded != null) {
            return encoded.clone();
        }
        try {
            // Payload = mldsaRaw || tradRaw  (raw concatenation per §4.1)
            byte[] payload = new byte[mldsaRaw.length + tradRaw.length];
            System.arraycopy(mldsaRaw, 0, payload, 0, mldsaRaw.length);
            System.arraycopy(tradRaw,  0, payload, mldsaRaw.length, tradRaw.length);

            // Build AlgorithmIdentifier SEQUENCE { OID }
            DerOutputStream algId = new DerOutputStream();
            algId.putOID(CompositeAlgorithmId.getOID(algorithm));

            // Build outer SubjectPublicKeyInfo SEQUENCE { AlgorithmIdentifier, BIT STRING }
            DerOutputStream spki = new DerOutputStream();
            spki.write(DerValue.tag_Sequence, algId);
            spki.putBitString(payload);

            DerOutputStream out = new DerOutputStream();
            out.write(DerValue.tag_Sequence, spki);
            encoded = out.toByteArray();
            return encoded.clone();
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            encoded = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }
}
