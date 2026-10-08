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
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

/**
 * Composite private key as defined in draft-ietf-lamps-pq-composite-sigs §5.
 *
 * <p>The key is encoded as a OneAsymmetricKey (RFC 5958) whose privateKey OCTET
 * STRING payload is the raw concatenation of the component private keys per
 * §4.2 (SerializePrivateKey):
 *
 * <pre>
 * privateKey OCTET STRING payload = mldsaSeed (32 bytes) || tradSK
 * </pre>
 *
 * <p>The ML-DSA component ({@code mldsaSeed}) is always the 32-byte seed as
 * defined in Table 1 of the draft and FIPS 204 §7.2. The traditional component
 * ({@code tradRaw}) is the raw private key bytes appropriate to its algorithm
 * (ECPrivateKey per RFC 5915 without the publicKey field, raw EdDSA seed bytes,
 * or RSAPrivateKey per RFC 8017 Appendix A.1.2).
 *
 * <p>The first component is always ML-DSA; the second is the traditional
 * component.
 */
@SuppressWarnings("restriction")
final class CompositePrivateKey implements PrivateKey {

    private static final long serialVersionUID = 1L;

    /** Length of the ML-DSA seed in bytes (all parameter sets). */
    static final int MLDSA_SEED_LEN = 32;

    private final String algorithm;
    /** 32-byte ML-DSA seed. */
    private byte[] mldsaSeed;
    /** Raw traditional component private key bytes. */
    private byte[] tradRaw;
    /** Cached outer OneAsymmetricKey encoding (lazy). */
    private volatile byte[] encoded;
    private transient boolean destroyed = false;

    /**
     * Constructs a composite private key from the 32-byte ML-DSA seed and the
     * raw traditional component private key bytes.
     *
     * @param algorithm the composite algorithm name
     * @param mldsaSeed 32-byte ML-DSA seed (see FIPS 204 §7.2)
     * @param tradRaw   raw traditional component private key bytes
     */
    CompositePrivateKey(String algorithm, byte[] mldsaSeed, byte[] tradRaw) {
        this.algorithm = algorithm;
        this.mldsaSeed = mldsaSeed.clone();
        this.tradRaw = tradRaw.clone();
    }

    /**
     * Constructs a composite private key by parsing an outer OneAsymmetricKey
     * encoding whose privateKey OCTET STRING payload is
     * {@code mldsaSeed (32 bytes) || tradSK} per §4.2.
     *
     * @param algorithm the composite algorithm name
     * @param encoded   the outer OneAsymmetricKey (PKCS#8) encoding
     * @throws InvalidKeyException if the encoding cannot be parsed
     */
    CompositePrivateKey(String algorithm, byte[] encoded) throws InvalidKeyException {
        this.algorithm = algorithm;
        try {
            // Parse outer OneAsymmetricKey SEQUENCE { version, AlgorithmIdentifier,
            //     privateKey OCTET STRING }
            DerValue outer = new DerValue(encoded);
            if (outer.tag != DerValue.tag_Sequence) {
                throw new InvalidKeyException("Not a SEQUENCE");
            }
            // version INTEGER
            outer.getData().getInteger();
            // AlgorithmIdentifier SEQUENCE
            outer.getData().getDerValue();
            // privateKey OCTET STRING — payload is mldsaSeed || tradSK (raw, §4.2)
            byte[] payload = outer.getData().getOctetString();

            if (payload.length < MLDSA_SEED_LEN) {
                throw new InvalidKeyException(
                        "Composite private key payload too short: " + payload.length
                                + " < " + MLDSA_SEED_LEN);
            }
            this.mldsaSeed = Arrays.copyOfRange(payload, 0, MLDSA_SEED_LEN);
            this.tradRaw   = Arrays.copyOfRange(payload, MLDSA_SEED_LEN, payload.length);
            this.encoded = encoded.clone();
        } catch (IOException e) {
            throw new InvalidKeyException("Failed to decode composite private key", e);
        }
    }

    /** Returns a copy of the 32-byte ML-DSA seed. */
    byte[] getMLDSASeed() {
        checkDestroyed();
        return mldsaSeed.clone();
    }

    /** Returns the raw traditional component private key bytes. */
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
        return "PKCS#8";
    }

    /**
     * Returns the OneAsymmetricKey (PKCS#8) encoding of this composite key.
     *
     * <pre>
     * OneAsymmetricKey ::= SEQUENCE {
     *     version             INTEGER (0),
     *     privateKeyAlgorithm AlgorithmIdentifier,
     *     privateKey          OCTET STRING  -- mldsaSeed || tradSK (raw, §4.2)
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
            // Payload = mldsaSeed || tradRaw  (raw concatenation per §4.2)
            byte[] payload = new byte[mldsaSeed.length + tradRaw.length];
            System.arraycopy(mldsaSeed, 0, payload, 0, mldsaSeed.length);
            System.arraycopy(tradRaw,   0, payload, mldsaSeed.length, tradRaw.length);

            // Build AlgorithmIdentifier SEQUENCE { OID }
            DerOutputStream algId = new DerOutputStream();
            algId.putOID(CompositeAlgorithmId.getOID(algorithm));

            // Build outer OneAsymmetricKey SEQUENCE
            DerOutputStream pkcs8 = new DerOutputStream();
            pkcs8.putInteger(0);
            pkcs8.write(DerValue.tag_Sequence, algId);
            pkcs8.putOctetString(payload);

            DerOutputStream out = new DerOutputStream();
            out.write(DerValue.tag_Sequence, pkcs8);
            encoded = out.toByteArray();
            return encoded.clone();
        } catch (Exception e) {
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
            if (mldsaSeed != null) {
                Arrays.fill(mldsaSeed, (byte) 0);
                mldsaSeed = null;
            }
            if (tradRaw != null) {
                Arrays.fill(tradRaw, (byte) 0);
                tradRaw = null;
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
