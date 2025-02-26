/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;


import com.ibm.crypto.plus.provider.ock.OCKException;
import com.ibm.crypto.plus.provider.ock.XECKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

abstract class XDHKeyAgreement extends KeyAgreementSpi {

    private static final int SECRET_BUFFER_SIZE_X25519 = 32;
    private static final int SECRET_BUFFER_SIZE_X448 = 56;

    private OpenJCEPlusProvider provider = null;
    private long genCtx;
    private XECKey ockXecKeyPub = null;
    private XECKey ockXecKeyPriv = null;
    private byte[] secret = null;
    private String alg = null;

    XDHKeyAgreement(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this))
            throw new SecurityException("Integrity check failed for: " + provider.getName());

        this.provider = provider;
    }

    XDHKeyAgreement(OpenJCEPlusProvider provider, String Alg) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this))
            throw new SecurityException("Integrity check failed for: " + provider.getName());

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
        if (!(key instanceof XDHPublicKeyImpl))
            throw new InvalidKeyException("Key is not an XDHPublicKeyImpl");
        if (ockXecKeyPriv == null)
            throw new IllegalStateException(
                    "object is not initialized correctly (private key is not received)");

        XDHPublicKeyImpl xdhPublicKeyImpl = (XDHPublicKeyImpl) key;

        //Validate algs match for key and keyagreement
        if (this.alg != null
                && !(((NamedParameterSpec) ((XDHPublicKeyImpl) key).getParams())
                        .getName().equals(this.alg))) {
            throw new InvalidKeyException("Parameters must be " + this.alg);
        }

        ockXecKeyPub = xdhPublicKeyImpl.getOCKKey();

        // we've received a public key (from one of the other parties),
        // so we are ready to create the secret, which may be an
        // intermediate secret, in which case we wrap it into a
        // Diffie-Hellman public key object and return it.
        if (lastPhase == false) {
            throw new IllegalStateException("XDH can only be between two parties.");
        }

        try {
            int secrectBufferSize = 0;
            String curveName = ((NamedParameterSpec) xdhPublicKeyImpl.getParams()).getName();
            if (NamedParameterSpec.X25519.getName().equals(curveName)) {
                secrectBufferSize = SECRET_BUFFER_SIZE_X25519; // X25519 secret buffer size
            } else if (NamedParameterSpec.X448.getName().equals(curveName)) {
                secrectBufferSize = SECRET_BUFFER_SIZE_X448; // X448 secret buffer size
            } else {
                secrectBufferSize = 0; // Let OCK decide the size
            }
            this.secret = XECKey.computeECDHSecret(provider.getOCKContext(), genCtx,
                    ockXecKeyPub.getPKeyId(), ockXecKeyPriv.getPKeyId(), secrectBufferSize);
        } catch (OCKException e) {
            throw new IllegalStateException("Failed to generate secret", e);
        } catch (Exception e) {
            throw new InvalidKeyException("Failed to generate secret", e);
        }

        //Valdate the secret for Point has small order
        byte orValue = (byte) 0;
        for (int i = 0; i < secret.length; i++) {
            orValue |= secret[i];
        }

        if (orValue == (byte) 0) {
            throw new InvalidKeyException("Point has small order.");
        }

        return null;
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (secret == null)
            throw new IllegalStateException("Wrong state");
        if (ockXecKeyPriv == null || ockXecKeyPub == null)
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
        if (!(algorithm.equals("TlsPremasterSecret")))
            throw new NoSuchAlgorithmException("Only supported for algorithm TlsPremasterSecret");
        return new SecretKeySpec(engineGenerateSecret(), "TlsPremasterSecret");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset)
            throws IllegalStateException, ShortBufferException {
        if (secret == null)
            throw new IllegalStateException("Wrong state");
        if (sharedSecret == null)
            throw new ShortBufferException("No buffer provided for shared secret");

        byte[] secret = engineGenerateSecret();
        try {
            System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ShortBufferException(e.getMessage());
        }
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
     * @param params Added to satisfy API but never used. Can be null.
     * @param random Added to satisfy API but never used. Can be null.
     * @throws InvalidKeyException                if the given key is inappropriate for this key agreement,
     *                                            e.g., is of the wrong type or has an incompatible
     *                                            algorithm type.
     * @throws InvalidAlgorithmParameterException if the given parameters are inappropriate for this key
     *                                            agreement.
     */

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        // Check if parameter is a valid NamedParameterSpec instance
        if ((params != null) && !(params instanceof NamedParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Invalid Parameters: " + params);
        }

        if (!(key instanceof XDHPrivateKeyImpl)) {
            try {
                KeyFactory kf = KeyFactory.getInstance(this.alg);
                XECPrivateKeySpec spec = kf.getKeySpec(key, XECPrivateKeySpec.class);
                key = kf.generatePrivate(spec);
            } catch (Exception exception) {
                // should not happen
                throw new InvalidKeyException("KeyFactory is not working as expected");
            }
        }

        XDHPrivateKeyImpl xdhPrivateKeyImpl = (XDHPrivateKeyImpl) key;

        //Validate algs match for key and keyfactory
        if (this.alg != null
                && !(((NamedParameterSpec) ((XDHPrivateKeyImpl) key).getParams())
                        .getName().equals(this.alg))) {
            throw new InvalidKeyException("Parameters must be " + this.alg);
        }

        ockXecKeyPriv = xdhPrivateKeyImpl.getOCKKey();
        ockXecKeyPub = null; // in case object is being reused
    }

    public static final class X25519 extends XDHKeyAgreement {
        public X25519(OpenJCEPlusProvider provider) {
            super(provider, "X25519");
        }
    }

    ;

    public static final class X448 extends XDHKeyAgreement {
        public X448(OpenJCEPlusProvider provider) {
            super(provider, "X448");
        }
    }

    ;

    public static final class XDH extends XDHKeyAgreement {
        public XDH(OpenJCEPlusProvider provider) {
            super(provider);
        }
    }

    ;
}
