/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.RSAKey;
import java.io.IOException;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class RSAPrivateCrtKey extends PKCS8Key
        implements java.security.interfaces.RSAPrivateCrtKey, Serializable, Destroyable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = -4315189411360884318L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger modulus;
    private BigInteger publicExponent;
    private BigInteger privateExponent;
    private BigInteger primeP;
    private BigInteger primeQ;
    private BigInteger primeExponentP;
    private BigInteger primeExponentQ;
    private BigInteger crtCoefficient;
    private transient AlgorithmParameterSpec keyParams;

    private transient boolean destroyed = false;
    private transient RSAKey rsaKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt

    /**
     * Generate a new key from its encoding.
     * Returns a CRT key if possible and a non-CRT key otherwise.
     * Used by RSAKeyFactory.
     */
    public static java.security.interfaces.RSAPrivateKey newKey(OpenJCEPlusProvider provider,
            byte[] encoded) throws InvalidKeyException {
        RSAPrivateCrtKey key = new RSAPrivateCrtKey(provider, encoded);
        // check all CRT-specific components are available, if any one missing, return a non-CRT key instead
        if ((key.getPublicExponent().signum() == 0) || (key.getPrimeExponentP().signum() == 0)
                || (key.getPrimeExponentQ().signum() == 0) || (key.getPrimeP().signum() == 0)
                || (key.getPrimeQ().signum() == 0) || (key.getCrtCoefficient().signum() == 0)) {
            return new RSAPrivateKey(key.algid, provider, key.getModulus(),
                    key.getPrivateExponent());
        } else {
            return key;
        }
    }

    public RSAPrivateCrtKey(OpenJCEPlusProvider provider, BigInteger m, BigInteger pubEx,
            BigInteger privEx, BigInteger p, BigInteger q, BigInteger ep, BigInteger eq,
            BigInteger coef) throws InvalidKeyException, IOException {
        rsaPrivateCrtKey(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider, m,
                pubEx, privEx, p, q, ep, eq, coef);
    }

    public RSAPrivateCrtKey(AlgorithmId algId, OpenJCEPlusProvider provider, BigInteger m,
            BigInteger pubEx, BigInteger privEx, BigInteger p, BigInteger q, BigInteger ep,
            BigInteger eq, BigInteger coef) throws InvalidKeyException {


        rsaPrivateCrtKey(algId, provider, m, pubEx, privEx, p, q, ep, eq, coef);

    }


    public void rsaPrivateCrtKey(AlgorithmId algId, OpenJCEPlusProvider provider, BigInteger m,
            BigInteger pubEx, BigInteger privEx, BigInteger p, BigInteger q, BigInteger ep,
            BigInteger eq, BigInteger coef) throws InvalidKeyException {

        this.algid = algId;
        this.provider = provider;
        this.modulus = m;
        this.publicExponent = pubEx;
        this.privateExponent = privEx;
        this.primeP = p;
        this.primeQ = q;
        this.primeExponentP = ep;
        this.primeExponentQ = eq;
        this.crtCoefficient = coef;
        this.keyParams = RSAUtil.getParamSpec(algid);

        if (this.modulus == null || this.publicExponent == null || this.privateExponent == null
                || this.primeP == null || this.primeQ == null || this.primeExponentP == null
                || this.primeExponentQ == null || this.crtCoefficient == null) {
            throw new InvalidKeyException("RSA Key parameters cannot be null");
        }

        RSAKeyFactory.checkRSAProviderKeyLengths(this.provider, this.modulus.bitLength(),
                this.publicExponent);

        try {
            this.key = buildPrivateKeyBytes(m, pubEx, privEx, p, q, ep, eq, coef);
        } catch (IOException ioe) {
            throw new InvalidKeyException("could not DER encode: " + ioe.getMessage());
        }

        try {
            this.rsaKey = RSAKey.createPrivateKey(provider.getOCKContext(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public RSAPrivateCrtKey(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {
        decode(encoded);
        this.provider = provider;

        try {
            parseKeyBits();
        } catch (IOException e) {
            InvalidKeyException ike = new InvalidKeyException(
                    "Failed to parse key bits of encoded key");
            provider.setOCKExceptionCause(ike, e);
            throw ike;
        }

        RSAKeyFactory.checkRSAProviderKeyLengths(provider, modulus.bitLength(), publicExponent);

        try {
            this.rsaKey = RSAKey.createPrivateKey(provider.getOCKContext(), this.key);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public RSAPrivateCrtKey(OpenJCEPlusProvider provider, RSAKey rsaKey) throws Exception {
        rsaPrivateCrtKey(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider,
                rsaKey);
    }

    public RSAPrivateCrtKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws Exception {
        rsaPrivateCrtKey(algId, provider, rsaKey);
    }

    public void rsaPrivateCrtKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws Exception {
        this.provider = provider;

        try {
            this.algid = algId;
            this.key = rsaKey.getPrivateKeyBytes();
            this.rsaKey = rsaKey;
            this.keyParams = RSAUtil.getParamSpec(algid);
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
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

    RSAKey getOCKKey() {
        return this.rsaKey;
    }

    @Override
    public AlgorithmParameterSpec getParams() {
        return keyParams;
    }

    protected void parseKeyBits() throws IOException {
        try {
            DerValue encoding = new DerValue(key);

            int version = encoding.getData().getInteger();
            if (version != 0) {
                throw new IOException("Version must be 0");
            }
            this.modulus = encoding.getData().getPositiveBigInteger();
            this.publicExponent = encoding.getData().getPositiveBigInteger();
            this.privateExponent = encoding.getData().getPositiveBigInteger();
            this.primeP = encoding.getData().getPositiveBigInteger();
            this.primeQ = encoding.getData().getPositiveBigInteger();
            this.primeExponentP = encoding.getData().getPositiveBigInteger();
            this.primeExponentQ = encoding.getData().getPositiveBigInteger();
            this.crtCoefficient = encoding.getData().getPositiveBigInteger();
            if (encoding.getData().available() != 0) {
                throw new IOException("Invalid RSAPrivateCrtKey encoding, data overrun");
            }
        } catch (IOException e) {
            throw new IOException("Invalid RSA private key", e);
        }
    }

    private static byte[] buildPrivateKeyBytes(BigInteger m, BigInteger pubEx, BigInteger privEx,
            BigInteger p, BigInteger q, BigInteger ep, BigInteger eq, BigInteger coef)
            throws IOException {
        DerValue[] value = new DerValue[9]; // construct PKCS#1 - A.1.2 RSA
                                            // private key

        value[0] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, m.toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, pubEx.toByteArray());
        value[3] = new DerValue(DerValue.tag_Integer, privEx.toByteArray());
        value[4] = new DerValue(DerValue.tag_Integer, p.toByteArray());
        value[5] = new DerValue(DerValue.tag_Integer, q.toByteArray());
        value[6] = new DerValue(DerValue.tag_Integer, ep.toByteArray());
        value[7] = new DerValue(DerValue.tag_Integer, eq.toByteArray());
        value[8] = new DerValue(DerValue.tag_Integer, coef.toByteArray());

        DerOutputStream asn1RSAKey = new DerOutputStream();
        asn1RSAKey.putSequence(value);

        return asn1RSAKey.toByteArray();
    }

    @Override
    public BigInteger getPrivateExponent() {
        checkDestroyed();
        return this.privateExponent;
    }

    @Override
    public BigInteger getModulus() {
        checkDestroyed();
        return this.modulus;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        checkDestroyed();
        return this.crtCoefficient;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        checkDestroyed();
        return this.primeExponentP;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        checkDestroyed();
        return this.primeExponentQ;
    }

    @Override
    public BigInteger getPrimeP() {
        checkDestroyed();
        return this.primeP;
    }

    @Override
    public BigInteger getPrimeQ() {
        checkDestroyed();
        return this.primeQ;
    }

    @Override
    public BigInteger getPublicExponent() {
        checkDestroyed();
        return this.publicExponent;
    }

    protected Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.PRIVATE, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
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
            this.rsaKey = null;
            this.modulus = null;
            this.publicExponent = null;
            this.privateExponent = null;
            this.primeP = null;
            this.primeQ = null;
            this.primeExponentP = null;
            this.primeExponentQ = null;
            this.crtCoefficient = null;
            this.keyParams = null;
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


    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }

        if (object instanceof Key) {
            // This bytes
            byte[] thisBytes = this.getEncoded();

            // That bytes
            byte[] thatBytes = null;
            if (object instanceof PKCS8Key) {
                thatBytes = ((PKCS8Key) object).getEncoded();
            } else {
                thatBytes = ((Key) object).getEncoded();
            }

            // Time-constant comparison
            return java.security.MessageDigest.isEqual(thisBytes, thatBytes);
        }
        return false;
    }
}
