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
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * Composite public key as defined in draft-ietf-lamps-pq-composite-sigs §5.
 *
 * <p>The key is encoded as a SubjectPublicKeyInfo whose subjectPublicKey
 * BIT STRING payload is a DER SEQUENCE containing the two component
 * SubjectPublicKeyInfo encodings:
 *
 * <pre>
 * CompositePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
 * </pre>
 *
 * <p>The first element is always the ML-DSA component; the second is the
 * traditional component.
 */
@SuppressWarnings("restriction")
final class CompositePublicKey implements PublicKey, Destroyable {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    /** Full X.509 / SubjectPublicKeyInfo encoding of the ML-DSA component key. */
    private final byte[] mldsaEncoded;
    /** Full X.509 / SubjectPublicKeyInfo encoding of the traditional component key. */
    private final byte[] tradEncoded;
    /** Cached outer DER encoding (lazy). */
    private volatile byte[] encoded;
    private transient boolean destroyed = false;

    /**
     * Constructs a composite public key from the two already-encoded component
     * SubjectPublicKeyInfo byte arrays.
     *
     * @param algorithm    the composite algorithm name (e.g.
     *                     {@code "MLDSA44-ECDSA-P256-SHA256"})
     * @param mldsaEncoded SubjectPublicKeyInfo encoding of the ML-DSA component
     * @param tradEncoded  SubjectPublicKeyInfo encoding of the traditional
     *                     component
     */
    CompositePublicKey(String algorithm, byte[] mldsaEncoded, byte[] tradEncoded) {
        this.algorithm = algorithm;
        this.mldsaEncoded = mldsaEncoded.clone();
        this.tradEncoded = tradEncoded.clone();
    }

    /**
     * Constructs a composite public key by parsing an outer SubjectPublicKeyInfo
     * encoding whose BIT STRING payload is the composite DER SEQUENCE.
     *
     * @param algorithm the composite algorithm name
     * @param encoded   the outer SubjectPublicKeyInfo encoding
     * @throws InvalidKeyException if the encoding cannot be parsed
     */
    CompositePublicKey(String algorithm, byte[] encoded) throws InvalidKeyException {
        this.algorithm = algorithm;
        try {
            // Parse outer SubjectPublicKeyInfo
            DerValue outer = new DerValue(encoded);
            if (outer.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Not a SEQUENCE");
            }
            DerInputStream outerSeq = outer.getData();
            // Skip AlgorithmIdentifier
            outerSeq.getDerValue();
            // Read BIT STRING payload
            byte[] bitStringBytes = outerSeq.getBitString();

            // Parse inner SEQUENCE { BIT STRING, BIT STRING }
            DerValue inner = new DerValue(bitStringBytes);
            if (inner.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Composite payload is not a SEQUENCE");
            }
            DerInputStream innerSeq = inner.getData();
            this.mldsaEncoded = innerSeq.getBitString();
            this.tradEncoded = innerSeq.getBitString();
            this.encoded = encoded.clone();
        } catch (IOException e) {
            throw new InvalidKeyException("Failed to decode composite public key", e);
        }
    }

    /** Returns the SubjectPublicKeyInfo encoding of the ML-DSA component. */
    byte[] getMLDSAEncoded() {
        checkDestroyed();
        return mldsaEncoded.clone();
    }

    /** Returns the SubjectPublicKeyInfo encoding of the traditional component. */
    byte[] getTraditionalEncoded() {
        checkDestroyed();
        return tradEncoded.clone();
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
     * Returns the SubjectPublicKeyInfo encoding of this composite key.
     *
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *     algorithm   AlgorithmIdentifier,
     *     publicKey   BIT STRING   -- payload is CompositePublicKey SEQUENCE
     * }
     * CompositePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
     * </pre>
     */
    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        if (encoded != null) {
            return encoded.clone();
        }
        try {
            // Build inner SEQUENCE { BIT STRING(mldsaEncoded), BIT STRING(tradEncoded) }
            DerOutputStream innerSeq = new DerOutputStream();
            innerSeq.putBitString(mldsaEncoded);
            innerSeq.putBitString(tradEncoded);

            DerOutputStream payload = new DerOutputStream();
            payload.write(DerValue.tag_Sequence, innerSeq);

            // Build AlgorithmIdentifier SEQUENCE { OID }
            DerOutputStream algId = new DerOutputStream();
            algId.putOID(CompositeAlgorithmId.getOID(algorithm));

            // Build outer SubjectPublicKeyInfo
            DerOutputStream spki = new DerOutputStream();
            spki.write(DerValue.tag_Sequence, algId);
            spki.putBitString(payload.toByteArray());

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
