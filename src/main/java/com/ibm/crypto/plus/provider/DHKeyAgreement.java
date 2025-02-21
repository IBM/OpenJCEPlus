/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.DHKey;
import com.ibm.crypto.plus.provider.ock.OCKException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.security.util.KeyUtil;

public final class DHKeyAgreement extends KeyAgreementSpi {

    private OpenJCEPlusProvider provider = null;
    private boolean generateSecret = false;
    private BigInteger init_p = null;
    private BigInteger init_g = null;
    private BigInteger x; // the private value
    private BigInteger y;

    private DHKey ockDHKeyPub = null;
    private DHKey ockDHKeyPriv = null;

    private DHPublicKey dhPublicKey = null;
    private DHPrivateKey dhPrivateKey = null;

    private static class AllowKDF {
        private static final boolean VALUE = getValue();

        private static boolean getValue() {
            return Boolean.parseBoolean(
                System.getProperty("jdk.crypto.KeyAgreement.legacyKDF", "false"));
        }
    }

    public DHKeyAgreement(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    @Override
    protected Key engineDoPhase(Key key, boolean lastPhase)
            throws InvalidKeyException, IllegalStateException {
        if (!(key instanceof javax.crypto.interfaces.DHPublicKey)) {
            throw new InvalidKeyException("Key is not a DHPublicKey");
        }
        javax.crypto.interfaces.DHPublicKey dhPubKey;
        dhPubKey = (javax.crypto.interfaces.DHPublicKey) key;

        if (init_p == null || init_g == null) {
            throw new IllegalStateException("Not initialized");
        }

        // check if public key parameters are compatible with
        // initialized ones
        BigInteger pub_p = dhPubKey.getParams().getP();
        BigInteger pub_g = dhPubKey.getParams().getG();
        if (pub_p != null && !(init_p.equals(pub_p))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (pub_g != null && !(init_g.equals(pub_g))) {
            throw new InvalidKeyException("Incompatible parameters");
        }

        // validate the Diffie-Hellman public key
        KeyUtil.validate(dhPubKey);

        // store the y value
        this.y = dhPubKey.getY();

        if (!(dhPubKey instanceof com.ibm.crypto.plus.provider.DHPublicKey)) {

            dhPublicKey = new DHPublicKey(provider, dhPubKey.getEncoded());

            if (dhPublicKey.getY().compareTo(this.y) != 0) {
                throw new InvalidKeyException("Public keys do not match");
            }

        } else {
            dhPublicKey = new DHPublicKey(provider, dhPubKey.getEncoded());
        }
        ockDHKeyPub = dhPublicKey.getOCKKey();

        // we've received a public key (from one of the other parties),
        // so we are ready to create the secret, which may be an
        // intermediate secret, in which case we wrap it into a
        // Diffie-Hellman public key object and return it.
        generateSecret = true;
        if (lastPhase == false) {
            throw new IllegalStateException("DH can only be between two parties.");
        } else {
            return null;
        }
    }

    // There is a double lock on ockDHKeyPub and ockDHKeyPriv to ensure that the underlying native
    // pointers are not concurrently used by another DH operation. This is needed as the method
    // DHKey.computeDHSecret is not synchronized and not thread safe.
    // The method DHKey.computeDHSecret should NOT be synchronized for performance as that would create a global lock.
    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (generateSecret == false) {
            throw new IllegalStateException("Wrong state");
        }

        // Reset the key agreement here (in case anything goes wrong)
        generateSecret = false;
        byte[] secret = null;

        try {
            if (ockDHKeyPub == null) {
                throw new IllegalStateException("ockDHKeyPub is null");
            }
            if (ockDHKeyPriv == null) {
                throw new IllegalStateException("ockDHKeyPriv is null");
            }

            // Establish an order for which key to lock first based on their hashcode to avoid a deadlock
            DHKey locker1;
            DHKey locker2;

            if (System.identityHashCode(ockDHKeyPub) < System.identityHashCode(ockDHKeyPriv)) {
                locker1 = ockDHKeyPub;
                locker2 = ockDHKeyPriv;
            } else {
                locker1 = ockDHKeyPriv;
                locker2 = ockDHKeyPub;
            }
            synchronized (locker1) {
                synchronized (locker2) {
                    secret = DHKey.computeDHSecret(provider.getOCKContext(),
                            ockDHKeyPub.getDHKeyId(), ockDHKeyPriv.getDHKeyId());
                }
            }
        } catch (IllegalStateException ise) {
            throw new IllegalStateException(ise.getMessage());
        } catch (OCKException e) {
            IllegalStateException ise = new IllegalStateException(e.getMessage());
            provider.setOCKExceptionCause(ise, e);
            throw ise;
        }


        // Make the computed secert compatible with  IBMJCE provider
        BigInteger modulus = init_p;
        int expectedLen = (modulus.bitLength() + 7) >>> 3;

        // BigInteger.toByteArray will sometimes put a sign byte up front.
        // However, Keys are always positive, and the above sign bit isn't
        // actually used when representing keys. To obtain an array containing
        // exactly expectedLen bytes of magnitude, we strip any extra
        // leading 0's, or pad with 0's in case of a "short" secret.
        // This requirement can be found in RFC2631 2.1.2
        if (secret.length == expectedLen) {
            return secret;
        } else {
            byte[] result = new byte[expectedLen];
            // Array too short, pad it w/ leading 0s
            if (secret.length < expectedLen) {
                System.arraycopy(secret, 0, result, (expectedLen - secret.length), secret.length);
            } else {
                // Array too long, check and trim off the excess
                if ((secret.length == (expectedLen + 1)) && secret[0] == 0) {
                    // ignore the leading sign byte
                    System.arraycopy(secret, 1, result, 0, expectedLen);
                } else {
                    throw provider.providerException("Failed to generate secret",
                            new OCKException("secret is out-of-range"));
                }
            }
            return result;
        }


    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm)
            throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("null algorithm");
        }

        if (!algorithm.equalsIgnoreCase("TlsPremasterSecret") && !AllowKDF.VALUE) {
            throw new NoSuchAlgorithmException(
                    "Unsupported secret key " + "algorithm: " + algorithm);
        }

        byte[] secret = engineGenerateSecret();
        if (algorithm.equalsIgnoreCase("DESede") || algorithm.equalsIgnoreCase("TripleDES")) {
            // Triple DES
            return new DESedeKey(secret);
        } else if (algorithm.equalsIgnoreCase("AES")) {
            // AES
            int keysize = secret.length;
            SecretKeySpec skey = null;
            int idx = AESConstants.AES_KEYSIZES.length - 1;
            while (skey == null && idx >= 0) {
                // Generate the strongest key using the shared secret
                // assuming the key sizes in AESConstants class are
                // in ascending order
                if (keysize >= AESConstants.AES_KEYSIZES[idx]) {
                    keysize = AESConstants.AES_KEYSIZES[idx];
                    skey = new SecretKeySpec(secret, 0, keysize, "AES");
                }
                idx--;
            }
            if (skey == null) {
                throw new InvalidKeyException("Key material is too short");
            }
            return skey;
        } else if (algorithm.equals("TlsPremasterSecret")) {
            // remove leading zero bytes per RFC 5246 Section 8.1.2
            return new SecretKeySpec(KeyUtil.trimZeroes(secret), "TlsPremasterSecret");
        } else {
            throw new NoSuchAlgorithmException(
                    "Unsupported secret key " + "algorithm: " + algorithm);
        }
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

        byte[] secret = engineGenerateSecret();

        if ((sharedSecret.length - offset) < secret.length) {
            // allow user to regenerate secret with larger buffer
            generateSecret = true;
            throw new ShortBufferException("Buffer too short for shared secret");
        }
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);

        return secret.length;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        try {
            engineInit(key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(
                    "DHKeyAgreement init failed with no AlgorithmParameterSpec specified");
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        // ignore "random" parameter, because our implementation does not
        // require any source of randomness
        generateSecret = false;
        init_p = null;
        init_g = null;

        if (params != null && !(params instanceof DHParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Diffie-Hellman parameters expected");
        }
        if (!(key instanceof javax.crypto.interfaces.DHPrivateKey)) {
            throw new InvalidKeyException("Key is not a DHPrivateKey");
        }

        javax.crypto.interfaces.DHPrivateKey dhPrivKey;
        dhPrivKey = (javax.crypto.interfaces.DHPrivateKey) key;

        // check if private key parameters are compatible with
        // initialized ones
        if (params != null) {
            init_p = ((DHParameterSpec) params).getP();
            init_g = ((DHParameterSpec) params).getG();
        }

        BigInteger priv_p = dhPrivKey.getParams().getP();
        BigInteger priv_g = dhPrivKey.getParams().getG();
        if (init_p != null && priv_p != null && !(init_p.equals(priv_p))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if (init_g != null && priv_g != null && !(init_g.equals(priv_g))) {
            throw new InvalidKeyException("Incompatible parameters");
        }
        if ((init_p == null && priv_p == null) || (init_g == null && priv_g == null)) {
            throw new InvalidKeyException("Missing parameters");
        }
        init_p = priv_p;
        init_g = priv_g;

        // store the x value
        this.x = dhPrivKey.getX();

        if (!(dhPrivKey instanceof com.ibm.crypto.plus.provider.DHPrivateKey)) {
            // Use this constructor to preserve the public key bytes
            try {
                this.dhPrivateKey = new com.ibm.crypto.plus.provider.DHPrivateKey(provider,
                        dhPrivKey.getEncoded());
            } catch (IOException e) {
                throw new InvalidKeyException("Error constructing DHPrivateKey", e);
            }

            if (this.dhPrivateKey.getX().compareTo(this.x) != 0) {
                throw new InvalidKeyException("Private keys do not match");
            }
        } else
            this.dhPrivateKey = (com.ibm.crypto.plus.provider.DHPrivateKey) dhPrivKey;

        this.ockDHKeyPriv = dhPrivateKey.getOCKKey();
    }

}
