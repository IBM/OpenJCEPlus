/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.ECKey;
import com.ibm.crypto.plus.provider.ock.OCKException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

public final class ECDHKeyAgreement extends KeyAgreementSpi { // implements
                                                              // AlgorithmStatus
                                                              // {
    private OpenJCEPlusProvider provider = null;
    private boolean generateSecret = false;
    // private ECParameterSpec params;
    private EllipticCurve init_ec = null;
    private ECPoint init_generator = null;
    private BigInteger init_order = null;
    private int init_cofactor = 1;
    private BigInteger x; // the private value
    private ECPoint y;
    private ECKey ockEcKeyPub = null;
    private ECKey ockEcKeyPriv = null;
    private ECPublicKey ecPublicKey = null;
    private ECPrivateKey ecPrivateKey = null;
    private int secretLen;

    public ECDHKeyAgreement(OpenJCEPlusProvider provider) {
        // System.out.println ("In ECDHKeyAgreement");
        this.provider = provider;
    }

    /**
     * Executes the next phase of this key agreement with the given key that was
     * received from one of the other parties involved in this key agreement.
     *
     * @param key
     *            the key for this phase. For example, in the case of
     *            Diffie-Hellman between 2 parties, this would be the other
     *            party's Diffie-Hellman public key.
     * @param lastPhase
     *            flag which indicates whether or not this is the last phase of
     *            this key agreement.
     *
     * @return the (intermediate) key resulting from this phase, or null if this
     *         phase does not yield a key
     *
     * @exception InvalidKeyException
     *                if the given key is inappropriate for this phase.
     * @exception IllegalStateException
     *                if this key agreement has not been initialized.
     */

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (!(key instanceof java.security.interfaces.ECPublicKey)) {
            throw new InvalidKeyException("Key is not an ECPublicKey");
        }
        java.security.interfaces.ECPublicKey ecPubKey;
        ecPubKey = (java.security.interfaces.ECPublicKey) key;

        if (init_ec == null || init_generator == null || init_order == null) {
            throw new IllegalStateException("Not initialized");
        }

        // check if public key parameters are compatible with
        // initialized ones
        ECParameterSpec ecPubKeyParamSpec = ecPubKey.getParams();
        EllipticCurve pub_ec = ecPubKeyParamSpec.getCurve();
        ECPoint pub_generator = ecPubKeyParamSpec.getGenerator();
        BigInteger pub_order = ecPubKeyParamSpec.getOrder();
        int pub_cofactor = ecPubKeyParamSpec.getCofactor();

        if (pub_ec != null && !(init_ec.equals(pub_ec))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (pub_generator != null && !(init_generator.equals(pub_generator))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (pub_order != null && !(init_order.equals(pub_order))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (!(init_cofactor == pub_cofactor)) {
            throw new InvalidKeyException("Incompatible parameters");
        }

        int keyLenBits = ecPubKey.getParams().getCurve().getField().getFieldSize();
        secretLen = (keyLenBits + 7) >> 3;

        // store the y value
        this.y = ecPubKey.getW();

        if (!(ecPubKey instanceof com.ibm.crypto.plus.provider.ECPublicKey)) {
            // System.out.println ("ecPubKey is not an instance ECPublicKey");

            ecPublicKey = new ECPublicKey(provider, ecPubKey.getEncoded());

            if (ecPublicKey.getW().getAffineX().compareTo(this.y.getAffineX()) != 0) {
                throw new InvalidKeyException("Public key affine X values do not match");
            }

            if (ecPublicKey.getW().getAffineY().compareTo(this.y.getAffineY()) != 0) {
                throw new InvalidKeyException("Public key affine Y values do not match");
            }
        } else
            ecPublicKey = (com.ibm.crypto.plus.provider.ECPublicKey) ecPubKey;

        ockEcKeyPub = ecPublicKey.getOCKKey();

        // we've received a public key (from one of the other parties),
        // so we are ready to create the secret, which may be an
        // intermediate secret, in which case we wrap it into a
        // Diffie-Hellman public key object and return it.
        generateSecret = true;
        if (lastPhase == false) {
            throw new IllegalStateException("ECDH can only be between two parties.");
            // byte[] intermediate = engineGenerateSecret();
            // try {
            // //System.out.println ("Creating a new ECPublicKey");
            // // test multiphase exchanges
            // return new ECPublicKey(ECUtils.multiply(new BigInteger(1,
            // intermediate), init_generator, init_ec),
            // new ECParameterSpec(init_ec, init_generator, init_order,
            // init_cofactor));
            //
            // } catch (InvalidParameterSpecException ipe) {
            // throw new InvalidKeyException("Could not create intermediate
            // secret");
            // }
        } else {
            return null;
        }

    }

    // There is a double lock on ockEcKeyPub and ockEcKeyPriv to ensure that the underlying native
    // pointers are not concurrently used by another ECDH operation. This is needed as the method
    // ECKey.computeDHSecret is not synchronized and not thread safe.
    // The method ECKey.computeDHSecret should NOT be synchronized for performance as that would create a global lock.
    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (generateSecret == false) {
            throw new IllegalStateException("Wrong state");
        }

        // Reset the key agreement here (in case anything goes wrong)
        generateSecret = false;
        byte[] secret = null;
        try {
            // Establish an order for which key to lock first based on their hashcode to avoid a deadlock
            ECKey locker1;
            ECKey locker2;

            if (System.identityHashCode(ockEcKeyPub) < System.identityHashCode(ockEcKeyPriv)) {
                locker1 = ockEcKeyPub;
                locker2 = ockEcKeyPriv;
            } else {
                locker1 = ockEcKeyPriv;
                locker2 = ockEcKeyPub;
            }
            synchronized (locker1) {
                synchronized (locker2) {
                    secret = ECKey.computeECDHSecret(provider.getOCKContext(),
                            ockEcKeyPub.getEcKeyId(), ockEcKeyPriv.getEcKeyId());
                }
            }
        } catch (OCKException e) {
            throw new IllegalStateException(e.getMessage());
        } catch (Exception e) {
            throw provider.providerException("Failed to generate secret", e);
        }
        // );

        return secret;

    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm must not be null");
        }
        if (!(algorithm.equals("TlsPremasterSecret"))) {
            throw new NoSuchAlgorithmException("Only supported for algorithm TlsPremasterSecret");
        }
        return new SecretKeySpec(engineGenerateSecret(), "TlsPremasterSecret");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (generateSecret == false) {
            throw new IllegalStateException("Wrong state");
        }

        if (sharedSecret == null) {
            throw new ShortBufferException("No buffer provided for shared secret");
        }

        if (secretLen > sharedSecret.length - offset) {
            throw new ShortBufferException("Need " + secretLen
                + " bytes, only " + (sharedSecret.length - offset)
                + " available");
        }

        byte[] secret = engineGenerateSecret();

        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;

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
     * @param key
     *            the party's private information. For example, in the case of
     *            the Diffie-Hellman key agreement, this would be the party's
     *            own Diffie-Hellman private key.
     * @param random
     *            the source of randomness
     *
     * @exception InvalidKeyException
     *                if the given key is inappropriate for this key agreement,
     *                e.g., is of the wrong type or has an incompatible
     *                algorithm type.
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
     * @param key
     *            the party's private information. For example, in the case of
     *            the Diffie-Hellman key agreement, this would be the party's
     *            own Diffie-Hellman private key.
     * @param params
     *            the key agreement parameters
     * @param random
     *            the source of randomness
     *
     * @exception InvalidKeyException
     *                if the given key is inappropriate for this key agreement,
     *                e.g., is of the wrong type or has an incompatible
     *                algorithm type.
     * @exception InvalidAlgorithmParameterException
     *                if the given parameters are inappropriate for this key
     *                agreement.
     */

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // System.out.println ("Inside ECDHKeyAgreement EngineInit");
        generateSecret = false;
        init_ec = null;
        init_generator = null;
        init_order = null;
        init_cofactor = 1;

        if (params != null
                && !(params instanceof ECParameterSpec || params instanceof ECGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("EC parameters expected");
        }
        if (params instanceof ECGenParameterSpec) {
            ECParameterSpec tmpPS = ECNamedCurve
                    .getECParameterSpec(((ECGenParameterSpec) params).getName());
            if (tmpPS != null) {
                params = tmpPS;
            } else {
                throw new InvalidAlgorithmParameterException(
                        "ECGenParameterSpec curve name not supported");
            }
        }
        if (!(key instanceof java.security.interfaces.ECPrivateKey)) {
            throw new InvalidKeyException("Key is not an ECPrivateKey");
        }
        java.security.interfaces.ECPrivateKey ecPrivKey = (java.security.interfaces.ECPrivateKey) key;
        ECUtils.checkPrivateKey(ecPrivKey);
        // check if private key parameters are compatible with
        // initialized ones
        if (params != null) {
            init_ec = ((ECParameterSpec) params).getCurve();
            init_generator = ((ECParameterSpec) params).getGenerator();
            init_order = ((ECParameterSpec) params).getOrder();
            init_cofactor = ((ECParameterSpec) params).getCofactor();
        }
        ECParameterSpec ecPrivKeyParamSpec = ecPrivKey.getParams();
        EllipticCurve priv_ec = ecPrivKeyParamSpec.getCurve();
        ECPoint priv_generator = ecPrivKeyParamSpec.getGenerator();
        BigInteger priv_order = ecPrivKeyParamSpec.getOrder();
        int priv_cofactor = ecPrivKeyParamSpec.getCofactor();
        if (init_ec != null && priv_ec != null && !(init_ec.equals(priv_ec))) {
            throw new InvalidKeyException("Incompatible parameters(ec)");
        }
        if (init_generator != null && priv_generator != null
                && !(init_generator.equals(priv_generator))) {
            throw new InvalidKeyException("Incompatible parameters(generator)");
        }
        if (init_order != null && priv_order != null && !(init_order.equals(priv_order))) {
            throw new InvalidKeyException("Incompatible parameters(order)");
        }
        if ((params != null) && !(init_cofactor == priv_cofactor)) {
            throw new InvalidKeyException("Incompatible parameters(priv_cofactor)");
        }
        if ((init_ec == null && priv_ec == null)
                || (init_generator == null && priv_generator == null)
                || (init_order == null && priv_order == null)) {
            throw new InvalidKeyException("Missing parameters");
        }
        init_ec = priv_ec;
        init_generator = priv_generator;
        init_order = priv_order;
        init_cofactor = priv_cofactor;

        // System.out.println ("init_ec=" + init_ec);
        // System.out.println ("init_ec=" + init_generator);
        // System.out.println ("init_ec=" + init_order);
        // System.out.println ("init_ec=" + init_cofactor);
        this.x = ecPrivKey.getS();
        if (!(ecPrivKey instanceof com.ibm.crypto.plus.provider.ECPrivateKey)) {
            // System.out.println ("ecPrivKey is not an instance ECPrivateKey");
            // Use this constructor to preserve the public key bytes

            try {
                ecPrivateKey = new ECPrivateKey(provider, ecPrivKey.getS(), ecPrivKey.getParams());
            } catch (InvalidParameterSpecException e) {
                throw new InvalidKeyException("Private keys do not match");
            }
            // ecPrivateKey = new ECPrivateKey(provider,
            // ecPrivKey.getEncoded());

            if (ecPrivateKey.getS().compareTo(this.x) != 0) {
                throw new InvalidKeyException("Private keys do not match");
            }
        } else
            ecPrivateKey = (com.ibm.crypto.plus.provider.ECPrivateKey) ecPrivKey;

        ockEcKeyPriv = ecPrivateKey.getOCKKey();

    }

}
