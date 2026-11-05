/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.NativeCryptoSelector;
import com.ibm.crypto.plus.provider.base.NativeInterface;
import com.ibm.crypto.plus.provider.base.XECKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

abstract class XDHKeyAgreement extends KeyAgreementSpi {

    private OpenJCEPlusProvider provider = null;
    private long genCtx;
    private String curveName;
    private XECKey nativeXecKeyPub = null;
    private XECKey nativeXecKeyPriv = null;
    private byte[] secret;
    private String alg = null;
    private NativeInterface nativeInterface = null;

    XDHKeyAgreement(OpenJCEPlusProvider provider) {
        this.provider = provider;
    }

    XDHKeyAgreement(OpenJCEPlusProvider provider, String Alg) {
        this.provider = provider;
        this.alg = Alg;
    }

    /**
     * Executes the next phase of this key agreement with the given key that was
     * received from one of the other parties involved in this key agreement.
     *
     * @param key       the key for this phase. For example, in the case of
     *                  Diffie-Hellman between 2 parties, this would be the other
     *                  party's Diffie-Hellman public key.
     * @param lastPhase flag which indicates whether or not this is the last phase of
     *                  this key agreement.
     * @return the (intermediate) key resulting from this phase, or null if this
     * phase does not yield a key (which is the case of X25519/X448 keys)
     * @throws InvalidKeyException   if the given key is inappropriate for this phase.
     * @throws IllegalStateException if this key agreement has not been initialized.
     */

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {

        clearSecret();
        this.nativeXecKeyPub = null;

        if (!(key instanceof XECPublicKey)) {
            throw new InvalidKeyException("Unsupported key type");
        }

        if (nativeXecKeyPriv == null) {
            throw new IllegalStateException(
                    "object is not initialized correctly "
                            + "(private key is not received)");
        }

        if (lastPhase == false) {
            throw new IllegalStateException(
                    "XDH can only be between two parties.");
        }

        // The factory translates foreign keys and keys from another backend
        // into a key usable by this KeyAgreement's backend.
        try {
            key = (XDHPublicKeyImpl) XDHKeyFactory.toXECKey(
                    this.provider, this.alg, key, this.nativeInterface);
        } catch (Exception exception) {
            throw new InvalidKeyException(
                    "Unable to translate key", exception);
        }

        XDHPublicKeyImpl xdhPublicKeyImpl = (XDHPublicKeyImpl) key;
        NamedParameterSpec keyParams = (NamedParameterSpec) xdhPublicKeyImpl.getParams();

        // Validate that the public and private keys use the same curve.
        if (!keyParams.getName().equalsIgnoreCase(this.curveName)) {
            throw new InvalidKeyException(
                    "Public and private keys must use the same parameters");
        }

        nativeXecKeyPub = xdhPublicKeyImpl.getNativeKey();

        try {
            this.secret = XECKey.computeECDHSecret(
                    genCtx,
                    nativeXecKeyPub.getPKeyId(),
                    nativeXecKeyPriv.getPKeyId(),
                    this.nativeInterface);
        } catch (Exception e) {
            throw new InvalidKeyException(
                    "Failed to generate secret", e);
        }

        byte orValue = (byte) 0;

        for (int i = 0; i < this.secret.length; i++) {
            orValue |= this.secret[i];
        }

        if (orValue == (byte) 0) {
            this.secret = null;
            throw new InvalidKeyException("Point has small order.");
        }

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (secret == null)
            throw new IllegalStateException("Wrong state");
        if (nativeXecKeyPriv == null || nativeXecKeyPub == null)
            throw new IllegalStateException("private/public key is not received");

        byte[] result = secret;

        // Reset the key agreement here (in case anything goes wrong)
        secret = null;

        return result;
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (algorithm == null)
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        if (!(algorithm.equalsIgnoreCase("TlsPremasterSecret")
                || algorithm.equalsIgnoreCase("Generic"))) {
            throw new NoSuchAlgorithmException(
                    "Unsupported secret key algorithm: " + algorithm);
        }
        return new SecretKeySpec(engineGenerateSecret(), algorithm);
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (secret == null) {
            throw new IllegalStateException("Wrong state");
        }

        if (sharedSecret == null || offset < 0 || offset > sharedSecret.length
                || secret.length > sharedSecret.length - offset) {
            throw new ShortBufferException(
                    "Insufficient buffer for shared secret");
        }

        int length = secret.length;
        System.arraycopy(secret, 0, sharedSecret, offset, length);
        clearSecret();
        return length;
    }

    /**
     * Initializes this key agreement with the given key and source of
     * randomness. The given key is required to contain all the algorithm
     * parameters required for this key agreement.
     *
     * <p>
     * If the key agreement algorithm requires random bytes, it gets them from
     * the given source of randomness, <code>random</code>. However, if the
     * underlying algorithm implementation does not require any random bytes,
     * <code>random</code> is ignored.
     *
     * @param key    the party's private information. For example, in the case of
     *               the Diffie-Hellman key agreement, this would be the party's
     *               own Diffie-Hellman private key.
     * @param random Added to satisfy API but never used. Can be null.
     * @throws InvalidKeyException if the given key is inappropriate for this key agreement,
     *                             e.g., is of the wrong type or has an incompatible
     *                             algorithm type.
     */

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            // never happens, because we did not pass any parameters
        }

    }

    /**
     * Initializes this key agreement with the given key, set of algorithm
     * parameters, and source of randomness.
     *
     * @param key    the party's private information. For example, in the case of
     *               the Diffie-Hellman key agreement, this would be the party's
     *               own Diffie-Hellman private key.
     * @param params optional parameters that must match the private key
     * @param random Added to satisfy API but never used. Can be null.
     * @throws InvalidKeyException                if the given key is inappropriate for this key agreement,
     *                                            e.g., is of the wrong type or has an incompatible
     *                                            algorithm type.
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this key
     *                                            agreement.
     */

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params,
            SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        clearSecret();
        this.nativeXecKeyPriv = null;
        this.nativeXecKeyPub = null;
        this.nativeInterface = null;
        this.curveName = null;

        if (!(key instanceof XECPrivateKey)) {
            throw new InvalidKeyException("Unsupported key type");
        }

        String configAlgName = this.alg;

        if (configAlgName == null) {
            configAlgName = "XDH";
        }

        try {
            this.nativeInterface =
                    NativeCryptoSelector.selectBackend(
                            this.provider, "KeyAgreement", configAlgName);
        } catch (Exception e) {
            throw new InvalidKeyException(
                    "Unable to select XDH KeyAgreement backend", e);
        }

        // The factory translates foreign keys and keys from another backend
        // into a key usable by this KeyAgreement's backend.
        try {
            key = (XDHPrivateKeyImpl) XDHKeyFactory.toXECKey(
                    this.provider, this.alg, key, this.nativeInterface);
        } catch (Exception exception) {
            throw new InvalidKeyException("Unable to translate key", exception);
        }

        // Check if parameter is a valid NamedParameterSpec instance.
        XDHPrivateKeyImpl xdhPrivateKeyImpl = (XDHPrivateKeyImpl) key;
        NamedParameterSpec keyParams =
                (NamedParameterSpec) xdhPrivateKeyImpl.getParams();

        // Check that the private key matches the KeyAgreement algorithm.
        if (this.alg != null
                && !this.alg.equalsIgnoreCase(keyParams.getName())) {
            throw new InvalidKeyException(
                    "Parameters must be " + this.alg
                            + " but is " + keyParams.getName());
        }

        // If parameters were supplied, they must match the private key.
        if (params != null) {
            if (!(params instanceof NamedParameterSpec)) {
                throw new InvalidAlgorithmParameterException(
                        "Parameters must be NamedParameterSpec");
            }

            NamedParameterSpec requestedParams = (NamedParameterSpec) params;

            if (!requestedParams.getName().equalsIgnoreCase(keyParams.getName())) {
                throw new InvalidAlgorithmParameterException(
                        "Parameters must match the private key parameters");
            }
        }
        this.curveName = keyParams.getName();
        nativeXecKeyPriv = xdhPrivateKeyImpl.getNativeKey();
    }

    private void clearSecret() {
        if (secret != null) {
            Arrays.fill(secret, (byte) 0);
            secret = null;
        }
    }

    public static final class X25519 extends XDHKeyAgreement {
        public X25519(OpenJCEPlusProvider provider) {
            super(provider, "X25519");
        }
    }

    public static final class X448 extends XDHKeyAgreement {
        public X448(OpenJCEPlusProvider provider) {
            super(provider, "X448");
        }
    }

    public static final class XDH extends XDHKeyAgreement {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }
}
