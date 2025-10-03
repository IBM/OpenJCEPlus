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
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import sun.security.pkcs.PKCS8Key;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

final class RSAPrivateKey extends PKCS8Key
        implements java.security.interfaces.RSAPrivateKey, Serializable, Destroyable {

    // Field serialVersionUID per tag [SERIALIZATION] in DesignNotes.txt
    private static final long serialVersionUID = -4315189411360884318L;

    private OpenJCEPlusProvider provider = null;
    private BigInteger modulus;
    private BigInteger privateExponent;
    private BigInteger publicExponent = BigInteger.ZERO;
    private BigInteger primeP = BigInteger.ZERO;
    private BigInteger primeQ = BigInteger.ZERO;
    private BigInteger primeExponentP = BigInteger.ZERO;
    private BigInteger primeExponentQ = BigInteger.ZERO;
    private BigInteger crtCoefficient = BigInteger.ZERO;

    private transient boolean destroyed = false;
    private transient RSAKey rsaKey = null; // Transient per tag [SERIALIZATION] in DesignNotes.txt
    private transient AlgorithmParameterSpec keyParams;

    public RSAPrivateKey(OpenJCEPlusProvider provider, BigInteger m, BigInteger privEx)
            throws InvalidKeyException, IOException {
        this(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider, m, privEx);
    }

    public RSAPrivateKey(AlgorithmId algId, OpenJCEPlusProvider provider, BigInteger m,
            BigInteger privEx) throws InvalidKeyException {
        this.algid = algId;
        this.provider = provider;
        this.modulus = m;
        this.privateExponent = privEx;
        this.keyParams = RSAUtil.getParamSpec(this.algid);


        if (this.modulus == null || this.privateExponent == null) {
            throw new InvalidKeyException("RSA Key parameters cannot be null");
        }

        RSAKeyFactory.checkRSAProviderKeyLengths(this.provider, this.modulus.bitLength(), null);

        try {
            this.privKeyMaterial = buildPrivateKeyBytes(m, privEx);
        } catch (IOException ioe) {
            throw new InvalidKeyException("could not DER encode: " + ioe.getMessage());
        }

        try {
            this.rsaKey = RSAKey.createPrivateKey(provider.getOCKContext(), this.privKeyMaterial);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public RSAPrivateKey(OpenJCEPlusProvider provider, byte[] encoded) throws InvalidKeyException {
        super(encoded);
        this.provider = provider;
        try {
            parseKeyBits();
        } catch (IOException e) {
            InvalidKeyException ike = new InvalidKeyException(
                    "Failed to parse key bits of encoded key");
            provider.setOCKExceptionCause(ike, e);
            throw ike;
        }

        RSAKeyFactory.checkRSAProviderKeyLengths(provider, modulus.bitLength(), null);

        try {
            this.rsaKey = RSAKey.createPrivateKey(provider.getOCKContext(), this.privKeyMaterial);
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public RSAPrivateKey(OpenJCEPlusProvider provider, RSAKey rsaKey) throws Exception {
        rsaPrivateKey(new AlgorithmId(ObjectIdentifier.of("1.2.840.113549.1.1.1")), provider,
                rsaKey);
    }

    public RSAPrivateKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws Exception {

        rsaPrivateKey(algId, provider, rsaKey);
    }


    public void rsaPrivateKey(AlgorithmId algId, OpenJCEPlusProvider provider, RSAKey rsaKey)
            throws Exception {
        this.provider = provider;

        try {
            this.algid = algId;
            this.privKeyMaterial = rsaKey.getPrivateKeyBytes();
            this.rsaKey = rsaKey;
            this.keyParams = RSAUtil.getParamSpec(algId);
            parseKeyBits();
        } catch (Exception exception) {
            InvalidKeyException ike = new InvalidKeyException("Failed to create RSA private key");
            provider.setOCKExceptionCause(ike, exception);
            throw ike;
        }
    }

    public static RSAPrivateKey newKey(OpenJCEPlusProvider provider, byte[] encoded)
            throws InvalidKeyException {
        RSAPrivateKey key = new RSAPrivateKey(provider, encoded);
        return key;
    }

    public static RSAPrivateKey newKey(OpenJCEPlusProvider provider, BigInteger m, BigInteger p)
            throws InvalidKeyException, IOException {
        RSAPrivateKey key = new RSAPrivateKey(provider, m, p);
        return key;
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

    // see JCA doc
    @Override
    public AlgorithmParameterSpec getParams() {
        return keyParams;
    }



    protected void parseKeyBits() throws IOException {
        try {
            DerValue encoding = new DerValue(this.privKeyMaterial);

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
                throw new IOException("Invalid RSAPrivateKey encoding, data overrun");
            }
        } catch (IOException e) {
            throw new IOException("Invalid RSA private key", e);
        }
    }

    private static byte[] buildPrivateKeyBytes(BigInteger m, BigInteger privEx) throws IOException {
        DerValue[] value = new DerValue[9]; // construct PKCS#1 - A.1.2 RSA
        // private key

        value[0] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[1] = new DerValue(DerValue.tag_Integer, m.toByteArray());
        value[2] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[3] = new DerValue(DerValue.tag_Integer, privEx.toByteArray());
        value[4] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[5] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[6] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[7] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());
        value[8] = new DerValue(DerValue.tag_Integer, BigInteger.ZERO.toByteArray());

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

    @java.io.Serial
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
            if (this.privKeyMaterial != null) {
                Arrays.fill(this.privKeyMaterial, (byte) 0x00);
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
}
