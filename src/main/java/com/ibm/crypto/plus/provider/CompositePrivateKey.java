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
import java.security.PrivateKey;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * Composite private key as defined in draft-ietf-lamps-pq-composite-sigs §5.
 *
 * <p>The key is encoded as a OneAsymmetricKey (PKCS#8) whose privateKey OCTET
 * STRING payload is a DER SEQUENCE containing the two component
 * OneAsymmetricKey encodings:
 *
 * <pre>
 * CompositePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
 * </pre>
 *
 * <p>The first element is always the ML-DSA component; the second is the
 * traditional component.
 */
@SuppressWarnings("restriction")
final class CompositePrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;

    private final String algorithm;
    /** PKCS#8 encoding of the ML-DSA component private key. */
    private byte[] mldsaEncoded;
    /** PKCS#8 encoding of the traditional component private key. */
    private byte[] tradEncoded;
    /** Cached outer PKCS#8 encoding (lazy). */
    private volatile byte[] encoded;
    private transient boolean destroyed = false;

    /**
     * Constructs a composite private key from the two already-encoded component
     * PKCS#8 byte arrays.
     *
     * @param algorithm   the composite algorithm name
     * @param mldsaEncoded PKCS#8 encoding of the ML-DSA component
     * @param tradEncoded  PKCS#8 encoding of the traditional component
     */
    CompositePrivateKey(String algorithm, byte[] mldsaEncoded, byte[] tradEncoded) {
        this.algorithm = algorithm;
        this.mldsaEncoded = mldsaEncoded.clone();
        this.tradEncoded = tradEncoded.clone();
    }

    /**
     * Constructs a composite private key by parsing an outer PKCS#8 encoding
     * whose privateKey OCTET STRING payload is the composite DER SEQUENCE.
     *
     * @param algorithm the composite algorithm name
     * @param encoded   the outer PKCS#8 encoding
     * @throws InvalidKeyException if the encoding cannot be parsed
     */
    CompositePrivateKey(String algorithm, byte[] encoded) throws InvalidKeyException {
        this.algorithm = algorithm;
        try {
            // Parse outer OneAsymmetricKey SEQUENCE
            DerValue outer = new DerValue(encoded);
            if (outer.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Not a SEQUENCE");
            }
            DerInputStream outerSeq = outer.getData();
            // version INTEGER
            outerSeq.getInteger();
            // AlgorithmIdentifier SEQUENCE
            outerSeq.getDerValue();
            // privateKey OCTET STRING  — payload is composite SEQUENCE
            byte[] privKeyOctets = outerSeq.getOctetString();

            // Parse inner SEQUENCE { OneAsymmetricKey, OneAsymmetricKey }
            DerValue inner = new DerValue(privKeyOctets);
            if (inner.tag == DerValue.tag_OctetString) {
                inner = new DerValue(inner.getOctetString());
            }
            if (inner.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Composite payload is not a SEQUENCE");
            }
            DerInputStream innerSeq = inner.getData();
            this.mldsaEncoded = innerSeq.getDerValue().toByteArray();
            this.tradEncoded = innerSeq.getDerValue().toByteArray();
            this.encoded = encoded.clone();
        } catch (IOException e) {
            throw new InvalidKeyException("Failed to decode composite private key", e);
        }
    }

    /** Returns the PKCS#8 encoding of the ML-DSA component. */
    byte[] getMLDSAEncoded() {
        checkDestroyed();
        return mldsaEncoded.clone();
    }

    /** Returns the PKCS#8 encoding of the traditional component. */
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
        return "PKCS#8";
    }

    /**
     * Returns the PKCS#8 encoding of this composite key.
     *
     * <pre>
     * OneAsymmetricKey ::= SEQUENCE {
     *     version            INTEGER (0),
     *     privateKeyAlgorithm AlgorithmIdentifier,
     *     privateKey         OCTET STRING  -- payload: composite SEQUENCE
     * }
     * CompositePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
     * </pre>
     */
    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        if (encoded != null) {
            return encoded.clone();
        }
        try {
            // Build inner SEQUENCE { mldsaEncoded, tradEncoded }
            DerOutputStream innerSeq = new DerOutputStream();
            innerSeq.write(mldsaEncoded);
            innerSeq.write(tradEncoded);

            DerOutputStream payload = new DerOutputStream();
            payload.write(DerValue.tag_Sequence, innerSeq);

            // Build AlgorithmIdentifier SEQUENCE { OID }
            DerOutputStream algId = new DerOutputStream();
            algId.putOID(CompositeAlgorithmId.getOID(algorithm));

            // Build outer OneAsymmetricKey
            DerOutputStream pkcs8 = new DerOutputStream();
            pkcs8.putInteger(0);
            pkcs8.write(DerValue.tag_Sequence, algId);
            pkcs8.putOctetString(payload.toByteArray());

            DerOutputStream out = new DerOutputStream();
            out.write(DerValue.tag_Sequence, pkcs8);
            encoded = out.toByteArray();
            return encoded.clone();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Destroys this key by zeroing the private key material.
     *
     * @throws DestroyFailedException never thrown
     */
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            if (mldsaEncoded != null) {
                Arrays.fill(mldsaEncoded, (byte) 0);
                mldsaEncoded = null;
            }
            if (tradEncoded != null) {
                Arrays.fill(tradEncoded, (byte) 0);
                tradEncoded = null;
            }
            encoded = null;
        }
    }

    /** Returns whether this key has been destroyed. */
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }
}
