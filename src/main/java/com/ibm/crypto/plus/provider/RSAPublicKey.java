/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.RSAUtil.KeyType;
import com.ibm.crypto.plus.provider.ock.RSAKey;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.util.BitArray;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.X509Key;

final class RSAPublicKey extends X509Key
        implements java.security.interfaces.RSAPublicKey, Destroyable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = 8560764496984239182L;

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private OpenJCEPlusProvider provider = null;
    private BigInteger modulus = null;
    private BigInteger publicExponent = null;

    private transient RSAKey rsaKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt
    private transient boolean destroyed = false;
    private transient AlgorithmParameterSpec keyParams;

    public RSAPublicKey(OpenJCEPlusProvider provider, BigInteger m, BigInteger e)
            throws InvalidKeyException, IOException {
        rsaPublicKey(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider, m, e);
    }

    public RSAPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, BigInteger m, BigInteger e)
            throws InvalidKeyException {

        rsaPublicKey(algId, provider, m, e);
    }

    public void rsaPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, BigInteger m,
            BigInteger e) throws InvalidKeyException {
        this.provider = provider;
        this.algid = algId;
        this.modulus = m;
        this.publicExponent = e;
        this.keyParams = RSAUtil.getParamSpec(algId);

        RSAKeyFactory.checkRSAProviderKeyLengths(this.provider, this.modulus.bitLength(),
                this.publicExponent);
        checkExponentRange();

        try {
            byte[] keyArray = buildPublicKeyBytes(m, e);
            setKey(new BitArray(keyArray.length * 8, keyArray));
            encode();
        } catch (IOException ioe) {
            throw new InvalidKeyException("Could not DER encode: " + ioe.getMessage());
        }

        try {
            this.rsaKey = RSAKey.createPublicKey(provider.getOCKContext(), getKey().toByteArray(), provider);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public RSAPublicKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        this.provider = provider;

        decode(encoded);

        RSAKeyFactory.checkRSAProviderKeyLengths(this.provider, this.modulus.bitLength(),
                this.publicExponent);
        checkExponentRange();

        try {
            this.rsaKey = RSAKey.createPublicKey(provider.getOCKContext(), getKey().toByteArray(), provider);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
        try {
            // this will check the validity of params
            this.keyParams = RSAUtil.getParamSpec(algid);
        } catch (ProviderException e) {
            throw new InvalidKeyException(e);
        }
    }

    /**
    * Generate a new RSAPublicKey from the specified type and components.
    * Used by SunPKCS11 provider.
    */
    public static RSAPublicKey newKey(OpenJCEPlusProvider provider, KeyType type,
            AlgorithmParameterSpec params, BigInteger n, BigInteger e) throws InvalidKeyException {
        AlgorithmId rsaId = RSAUtil.createAlgorithmId(type, params);
        return new RSAPublicKey(rsaId, provider, n, e);
    }

    private void checkExponentRange() throws InvalidKeyException {
        // the exponent should be smaller than the modulus
        if (publicExponent.compareTo(modulus) >= 0) {
            throw new InvalidKeyException("exponent is larger than modulus");
        }

        // the exponent should be at least 3
        if (publicExponent.compareTo(THREE) < 0) {
            throw new InvalidKeyException("exponent is smaller than 3");
        }
    }


    public RSAPublicKey(OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws InvalidKeyException, IOException {
        rsaPublicKey(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider,
                rsaKey);
    }

    public RSAPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws InvalidKeyException {
        rsaPublicKey(algId, provider, rsaKey);
    }

    public void rsaPublicKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws InvalidKeyException {
        this.provider = provider;

        try {
            this.algid = algId;
            byte[] keyArray = rsaKey.getPublicKeyBytes();
            setKey(new BitArray(keyArray.length * 8, keyArray));
            this.rsaKey = rsaKey;
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA public key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }

        try {
            // this will check the validity of params
            this.keyParams = RSAUtil.getParamSpec(algid);
        } catch (ProviderException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    public BigInteger getModulus() {
        checkDestroyed();
        return this.modulus;
    }

    @Override
    public BigInteger getPublicExponent() {
        checkDestroyed();
        return this.publicExponent;
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

    // see JCA doc
    @Override
    public AlgorithmParameterSpec getParams() {
        return keyParams;
    }

    RSAKey getOCKKey() {
        return this.rsaKey;
    }

    private static byte[] buildPublicKeyBytes(BigInteger modulus, BigInteger publicExponent)
            throws IOException {
        DerValue[] value = new DerValue[2]; // construct PKCS#1 - A.1.1 RSA
                                            // public key

        value[0] = new DerValue(DerValue.tag_Integer, modulus.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, publicExponent.toByteArray());

        DerOutputStream asn1RSAKey = new DerOutputStream();
        asn1RSAKey.putSequence(value);

        return asn1RSAKey.toByteArray();
    }

    protected void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(getKey().toByteArray());

            // Get what has been written to this DerInputStream
            DerValue[] value = in.getSequence(2);

            // Get modulus and public exponent
            this.modulus = value[0].getPositiveBigInteger();
            this.publicExponent = value[1].getPositiveBigInteger();
        } catch (IOException e) {
            throw new InvalidKeyException("Invalid RSA public key", e);
        }
    }

    /**
     * Replace the RSAPublicKey key to be serialized.
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
            this.rsaKey = null;
            this.modulus = null;
            this.publicExponent = null;
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
