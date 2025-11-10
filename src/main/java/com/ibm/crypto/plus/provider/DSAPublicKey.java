/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.DSAKey;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgIdDSA;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

/**
 * An X.509 public key for the DSA Algorithm.
 *
 */
final class DSAPublicKey extends X509Key
        implements java.security.interfaces.DSAPublicKey, Serializable, Destroyable {

    private static final long serialVersionUID = 8751667575123698655L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger y; // the public key

    private transient boolean destroyed = false;
    private transient DSAKey dsaKey = null;

    /**
     * Create a new DSA public key from y, p, q, and g.
     *
     * @param y
     *            public key
     * @param p
     *            prime modulus
     * @param q
     *            prime divisor
     * @param g
     *            the number g
     */
    DSAPublicKey(OpenJCEPlusProvider provider, BigInteger y, BigInteger p, BigInteger q,
            BigInteger g) throws InvalidKeyException {
        this.algid = new AlgIdDSA(p, q, g);
        this.provider = provider;
        this.y = y;

        try {
            byte[] keyArray = new DerValue(DerValue.tag_Integer, y.toByteArray()).toByteArray();
            setKey(new BitArray(keyArray.length * 8, keyArray));
            encode();
        } catch (IOException e) {
            throw new InvalidKeyException("coud not DER encode y: " + e.getMessage());
        }

        try {
            byte[] publicKeyBytes = buildOCKPublicKeyBytes();
            this.dsaKey = DSAKey.createPublicKey(provider.getOCKContext(), publicKeyBytes, provider);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Make a DSA public key from its DER encoding (X.509).
     *
     * @param encoded
     *            the encoded bytes of the public key
     */
    DSAPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        decode(encoded);

        try {
            byte[] publicKeyBytes = buildOCKPublicKeyBytes();
            this.dsaKey = DSAKey.createPublicKey(provider.getOCKContext(), publicKeyBytes, provider);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    DSAPublicKey(OpenJCEPlusProvider provider, DSAKey dsaKey) throws InvalidKeyException {
        this.provider = provider;

        try {
            this.algid = new AlgorithmId(AlgorithmId.DSA_oid, new DerValue(dsaKey.getParameters()));

            byte[] keyArray = convertOCKPublicKeyBytes(dsaKey.getPublicKeyBytes());
            setKey(new BitArray(keyArray.length * 8, keyArray));
            this.dsaKey = dsaKey;
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA public key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Return the DSA parameters for the receiver.
     *
     * @return DSAParams the DSA parameters of this instance
     */
    @Override
    public DSAParams getParams() {
        checkDestroyed();
        try {
            if (algid instanceof DSAParams) {
                return (DSAParams) algid;
            } else {

                DSAParameterSpec paramSpec;
                AlgorithmParameters algParams = algid.getParameters();
                if (algParams == null) {

                    return null;
                }
                paramSpec = algParams.getParameterSpec(DSAParameterSpec.class);
                return (DSAParams) paramSpec;
            }
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Return the value of the public key.
     *
     * @param the
     *            value of y
     */
    @Override
    public BigInteger getY() {
        checkDestroyed();
        return this.y;
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return super.getAlgorithm();
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return super.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return super.getEncoded();
    }

    DSAKey getOCKKey() {
        return this.dsaKey;
    }

    protected void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(getKey().toByteArray());
            y = in.getBigInteger();
        } catch (IOException e) {
            throw new InvalidKeyException("Invalid DSA public key", e);
        }
    }

    private byte[] convertOCKPublicKeyBytes(byte[] publicKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(publicKeyBytes);
        DerValue[] inputValue = in.getSequence(4);
        BigInteger tempY = inputValue[0].getBigInteger();

        /* Only the first element of the sequence is used - 
         * BigInteger tempP = inputValue[1].getInteger();
        BigInteger tempQ = inputValue[2].getInteger();
        BigInteger tempG = inputValue[3].getInteger();*/

        DerValue outputValue = new DerValue(DerValue.tag_Integer, tempY.toByteArray());
        return outputValue.toByteArray();
    }

    private byte[] buildOCKPublicKeyBytes() throws IOException {
        DSAParams params = getParams();

        DerValue[] value = new DerValue[4];

        value[0] = new DerValue(DerValue.tag_Integer, this.y.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, params.getP().toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, params.getQ().toByteArray());
        value[3] = new DerValue(DerValue.tag_Integer, params.getG().toByteArray());

        try (DerOutputStream asn1Key = new DerOutputStream()) {
            asn1Key.putSequence(value);
            return asn1Key.toByteArray();
        }
    }

    public String toString() {
        return provider.getName() + " DSA Public Key:\n" + y.toString() + "\n";
    }

    /**
     * Replace the DSAPublicKey key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException
     *             if a new object representing this key could not be
     *             created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PUBLIC, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            setKey(new BitArray(0));
            this.dsaKey = null;
            this.y = null;
        }
    }

    /** Determines if this key has been destroyed. */
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
