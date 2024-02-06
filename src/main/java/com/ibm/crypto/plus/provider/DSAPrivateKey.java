/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.interfaces.DSAParams;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import com.ibm.crypto.plus.provider.ock.DSAKey;

import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.x509.AlgIdDSA;
import sun.security.x509.AlgorithmId;

/**
 * An X.509 private key for the DSA Algorithm.
 */
final class DSAPrivateKey extends PKCS8Key
        implements java.security.interfaces.DSAPrivateKey, Serializable, Destroyable {

    private static final long serialVersionUID = -358600541133686399L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger x; // the private key

    private transient boolean destroyed = false;
    private transient DSAKey dsaKey = null;

    /**
     * Create a DSA private key from x, p, q, and g.
     *
     * @param x
     *            the private key
     * @param p
     *            the number p
     * @param q
     *            the number q
     * @param g
     *            the number g
     */
    public DSAPrivateKey(OpenJCEPlusProvider provider, BigInteger x, BigInteger p, BigInteger q,
            BigInteger g) throws InvalidKeyException {

        this.algid = new AlgIdDSA(p, q, g);
        this.provider = provider;
        this.x = x;

        key = new DerValue(DerValue.tag_Integer, x.toByteArray()).toByteArray();

        try {
            byte[] privateKeyBytes = buildOCKPrivateKeyBytes();
            this.dsaKey = DSAKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Create a DSA private key from it's DER encoding (PKCS#8)
     *
     * @param encoded
     *            the encoded parameters.
     */
    public DSAPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;

        try {
            parseKeyBits();
            byte[] privateKeyBytes = buildOCKPrivateKeyBytes();
            this.dsaKey = DSAKey.createPrivateKey(provider.getOCKContext(), privateKeyBytes);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public DSAPrivateKey(OpenJCEPlusProvider provider, DSAKey dsaKey) throws InvalidKeyException {
        try {
            this.provider = provider;
            this.algid = new AlgorithmId(AlgorithmId.DSA_oid, new DerValue(dsaKey.getParameters()));
            this.key = convertOCKPrivateKeyBytes(dsaKey.getPrivateKeyBytes());

            this.dsaKey = dsaKey;
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create DSA private key",
                    exception);
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    /**
     * Returns the DSA parameters associated with this key, or null if the
     * parameters could not be parsed.
     *
     * @return DSAParams the DSA parameter of this instance
     */
    @Override
    public DSAParams getParams() {
        try {
            if (algid instanceof DSAParams) {
                return (DSAParams) algid;
            } else {
                DSAParameterSpec paramSpec;
                AlgorithmParameters algParams = algid.getParameters();
                if (algParams == null) {
                    return null;
                }
                paramSpec = (DSAParameterSpec) algParams.getParameterSpec(DSAParameterSpec.class);
                return (DSAParams) paramSpec;
            }
        } catch (InvalidParameterSpecException e) {
            return null;
        }
    }

    /**
     * Return the value of the private key.
     *
     * @return BigInteger the value of x
     */
    @Override
    public BigInteger getX() {
        return this.x;
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

    protected void parseKeyBits() throws IOException {
        DerInputStream in = new DerInputStream(key);

        try {
            x = in.getBigInteger();
        } catch (IOException e) {
            throw new IOException("Invalid DSA private key", e);
        }
    }

    private byte[] convertOCKPrivateKeyBytes(byte[] privateKeyBytes) throws IOException {
        DerInputStream in = new DerInputStream(privateKeyBytes);
        DerValue[] inputValue = in.getSequence(6);
        /* The first 5 values are there but we do need to use them 
         * BigInteger tempVersion = inputValue[0].getInteger();
        BigInteger tempP = inputValue[1].getInteger();
        BigInteger tempQ = inputValue[2].getInteger();
        BigInteger tempG = inputValue[3].getInteger();
        BigInteger tempY = inputValue[4].getInteger();*/
        BigInteger tempX = inputValue[5].getBigInteger();

        DerValue outputValue = new DerValue(DerValue.tag_Integer, tempX.toByteArray());
        return outputValue.toByteArray();
    }

    private byte[] buildOCKPrivateKeyBytes() throws IOException {
        DSAParams params = getParams();

        // Compute the public key
        //
        BigInteger y = params.getG().modPow(x, params.getP());

        DerValue[] value = new DerValue[6];

        value[0] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, params.getP().toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, params.getQ().toByteArray());
        value[3] = new DerValue(DerValue.tag_Integer, params.getG().toByteArray());
        value[4] = new DerValue(DerValue.tag_Integer, y.toByteArray()); // public
                                                                        // key
        value[5] = new DerValue(DerValue.tag_Integer, this.x.toByteArray()); // private
                                                                             // key
        try (DerOutputStream asn1Key = new DerOutputStream()) {
            asn1Key.putSequence(value);
            return asn1Key.toByteArray();
        }
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
            if (this.key != null) {
                Arrays.fill(this.key, (byte) 0x00);
            }
            this.dsaKey = null;
            this.x = null;
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

    /**
     * Compares two private keys. This returns false if the object with which
     * to compare is not of type <code>Key</code>.
     * Otherwise, we compare the private part of the key and the params to validate equivalence.
     * We can not compare encodings because there are 2 different ones and both can be the same
     * key.
     *
     * @param object the object with which to compare
     * @return {@code true} if this key has the same encoding as the
     *          object argument; {@code false} otherwise.
     */
    public boolean equals(Object object) {
        try {
            BigInteger i = (BigInteger) (object.getClass().getDeclaredMethod("getX")
                    .invoke(object));

            if (this == object) {
                return true;
            }
            if (object instanceof Key) {
                if (this.x.equals(i) && equals((DSAParams) this.getParams(), (DSAParams) (object
                        .getClass().getDeclaredMethod("getParams").invoke(object)))) {
                    return true;
                }
            }
        } catch (Exception e1) {
            //Should never get here
            //System.out.println("Object = Exception - " + e1.toString());
        }
        return false;
    }

    public static boolean equals(DSAParams spec1, DSAParams spec2) {
        if (spec1 == spec2) {
            return true;
        }

        if (spec1 == null || spec2 == null) {
            return false;
        }

        return (spec1.getP().equals(spec2.getP()) && spec1.getQ().equals(spec2.getQ())
                && spec1.getG().equals(spec2.getG()));
    }
}
