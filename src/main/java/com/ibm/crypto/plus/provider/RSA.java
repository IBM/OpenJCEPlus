/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.RSACipher;
import com.ibm.crypto.plus.provider.ock.RSAPadding;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.interfaces.RSAKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

public final class RSA extends CipherSpi {

    private OpenJCEPlusProvider provider = null;
    private RSACipher rsaCipher = null;
    private RSAPadding padding = RSAPadding.PKCS1Padding;
    private ByteBuffer msgBuffer = null;
    private AlgorithmParameterSpec spec = null;
    private String oaepHashAlgorithm = "SHA-1";
    private int msgLength = 0;
    private int keyType = -1;
    private boolean initialized = false;
    private boolean encrypting = true;

    private static final boolean doTypeChecking;
    private static final String DO_TYPE_CHECKING = "com.ibm.crypto.provider.DoRSATypeChecking";
    private static final boolean allowNonOAEPFIPS;
    private static final String ALLOW_NON_OAEP_FIPS = "com.ibm.openjceplusfips.allowNonOAEP";

    private final static byte[] B0 = new byte[0];

    static {
        doTypeChecking = Boolean.parseBoolean(System.getProperty(DO_TYPE_CHECKING, "true"));
        allowNonOAEPFIPS = Boolean.parseBoolean(System.getProperty(ALLOW_NON_OAEP_FIPS, "false"));
    }

    public RSA(OpenJCEPlusProvider provider) {
        this.provider = provider;
        try {
            this.rsaCipher = RSACipher.getInstance(provider.getOCKContext());
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize RSA cipher", e);
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inOffset, int inLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();
        byte[] output = new byte[engineGetOutputSize(0)];
        try {
            int outLen = engineDoFinal(input, inOffset, inLen, output, 0);
            if (outLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (ShortBufferException sbe) {
            throw provider.providerException("Failure in engineDoFinal", sbe);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inOffset, int inLen, byte[] output, int outOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();
        if (input != null) {
            internalUpdate(input, inOffset, inLen);
        }

        if (msgLength > msgBuffer.capacity()) {
            throw new IllegalBlockSizeException(
                    "Data must not be longer than " + msgBuffer.capacity() + " bytes");
        }

        try {
            int outLen = 0;
            if (this.encrypting) {
                if (this.padding.isPadding(RSAPadding.RSAPAD_NONE)
                        && msgLength != engineGetOutputSize(0)) {
                    byte[] paddedInput = new byte[engineGetOutputSize(0)];
                    System.arraycopy(this.msgBuffer.array(), 0, paddedInput,
                            paddedInput.length - msgLength, msgLength);
                    this.msgBuffer.clear();
                    this.msgBuffer.put(paddedInput);
                    this.msgLength = paddedInput.length;
                } else if (this.padding.isPadding(RSAPadding.RSAPAD_PKCS1)
                        && msgLength > pkcs1InputLimit()) {
                    throw new IllegalBlockSizeException(
                            "Data must not be longer than " + pkcs1InputLimit() + " bytes");
                } else if (this.padding.isPadding(RSAPadding.RSAPAD_OAEP)
                        && msgLength > oaepInputLimit()) {
                    throw new IllegalBlockSizeException(
                            "Data must not be longer than " + oaepInputLimit() + " bytes");
                }
                outLen = this.keyType == Cipher.PUBLIC_KEY
                        ? rsaCipher.publicEncrypt(this.padding, this.msgBuffer.array(), 0,
                                this.msgLength, output, outOffset)
                        : rsaCipher.privateEncrypt(this.padding, this.msgBuffer.array(), 0,
                                this.msgLength, output, outOffset);
                Arrays.fill(this.msgBuffer.array(), (byte) 0x00);
            } else {
                if (this.msgLength != engineGetOutputSize(0)) {
                    throw new BadPaddingException(
                            "message must be same length as key for rsa decryption");
                }
                outLen = this.keyType == Cipher.PUBLIC_KEY
                        ? rsaCipher.publicDecrypt(this.padding, this.msgBuffer.array(), 0,
                                this.msgLength, output, outOffset)
                        : rsaCipher.privateDecrypt(this.padding, this.msgBuffer.array(), 0,
                                this.msgLength, output, outOffset);
            }
            this.msgBuffer.clear();
            this.msgLength = 0; // reset cipher for another
                                // encryption/decryption
            return outLen;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (IllegalBlockSizeException ock_ibse) {
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (Exception e) {
            // Unsure of msg length behavior on failure. e.g. do we set it to 0?
            // do we clear the buffer?
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        RSAKey rsaKey = RSAKeyFactory.toRSAKey(provider, key);
        return rsaKey.getModulus().bitLength();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        checkCipherInitialized();
        try {
            return this.rsaCipher.getOutputSize();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineGetOutputSize", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if ((spec != null) && (spec instanceof OAEPParameterSpec)) {
            try {
                AlgorithmParameters params = AlgorithmParameters.getInstance("OAEP", provider);
                params.init(spec);
                return params;
            } catch (NoSuchAlgorithmException nsae) {
                throw new ProviderException(
                        "Cannot find OAEP " + " AlgorithmParameters implementation in "
                                + provider.getName() + " provider");
            } catch (InvalidParameterSpecException ipse) {
                throw new ProviderException("OAEPParameterSpec not supported");
            }
        } else {
            return null;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            internalInit(opmode, key, null);
        } catch (InvalidAlgorithmParameterException iape) {
            // never thrown when null parameters are used;
            // but re-throw it just in case
            InvalidKeyException ike = new InvalidKeyException("Wrong parameters");
            ike.initCause(iape);
            throw ike;
        }

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            internalInit(opmode, key, null);
        } else {
            try {
                OAEPParameterSpec spec = params.getParameterSpec(OAEPParameterSpec.class);
                internalInit(opmode, key, spec);
            } catch (InvalidParameterSpecException ipse) {
                InvalidAlgorithmParameterException iape = new InvalidAlgorithmParameterException(
                        "Wrong parameter");
                iape.initCause(ipse);
                throw iape;
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        internalInit(opmode, key, params);
    }

    private void internalInit(int opmode, Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if ((key == null) || (key.getEncoded().length == 0)) {
            throw new InvalidKeyException("key is null/empty");
        }

        if (!(key instanceof RSAKey))
            throw new InvalidKeyException("key was not an RSAKey");

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypting = true;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypting = false;
        } else {
            throw new InvalidKeyException("Invalid mode: " + opmode);
        }

        if (this.padding.getId() == RSAPadding.OAEPPadding.getId()) {
            if (params != null) {
                if (!(params instanceof OAEPParameterSpec)) {
                    throw new InvalidAlgorithmParameterException(
                            "Wrong parameters for OAEP Padding");
                }
                checkOAEPParameters((OAEPParameterSpec) params);
                this.spec = params;
            } else {
                this.spec = new OAEPParameterSpec(oaepHashAlgorithm, "MGF1", MGF1ParameterSpec.SHA1,
                        PSource.PSpecified.DEFAULT);
            }
        }

        RSAKey rsaKey = RSAKeyFactory.toRSAKey(provider, key);

        if (key instanceof java.security.interfaces.RSAPublicKey) {
            if (doTypeChecking) {
                if (!encrypting) {
                    throw new InvalidKeyException("Public Key cannot be used to decrypt.");
                }
            }
            try {
                RSAPublicKey rsaPub = (RSAPublicKey) rsaKey;
                rsaCipher.initialize(rsaPub.getOCKKey(), false);
                this.keyType = Cipher.PUBLIC_KEY;
            } catch (Exception e) {
                throw provider.providerException("Failure in internalInit", e);
            }
        } else if (key instanceof java.security.interfaces.RSAPrivateCrtKey) {
            if (doTypeChecking) {
                if (encrypting) {
                    throw new InvalidKeyException("Private Key cannot be used to encrypt.");
                }
            }
            try {
                RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) rsaKey;
                rsaCipher.initialize(rsaPriv.getOCKKey(), false);
                this.keyType = Cipher.PRIVATE_KEY;
            } catch (Exception e) {
                throw provider.providerException("Failure in internalInit", e);
            }
        } else if (key instanceof java.security.interfaces.RSAPrivateKey) {
            if (doTypeChecking) {
                if (encrypting) {
                    throw new InvalidKeyException("Private Key cannot be used to encrypt.");
                }
            }
            try {
                RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKey;
                rsaCipher.initialize(rsaPriv.getOCKKey(), true);
                this.keyType = Cipher.PRIVATE_KEY;
            } catch (Exception e) {
                throw provider.providerException("Failure in internalInit", e);
            }
        } else {
            throw new InvalidKeyException("key type not supported");
        }

        try {
            this.msgBuffer = ByteBuffer.allocate(rsaCipher.getOutputSize());
            this.msgLength = 0;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failure in internalInit", e);
        }

        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypting = true;
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypting = false;
        }
    }

    private void checkOAEPParameters(OAEPParameterSpec spec)
            throws InvalidAlgorithmParameterException {
        // ensure we are only supporting OAEPParameters.DEFAULT fields
        if (!("SHA-1".equals(spec.getDigestAlgorithm()))
                || !("MGF1".equals(spec.getMGFAlgorithm()))) {
            throw new InvalidAlgorithmParameterException("Only SHA-1 & MGF1 is supported for OAEP");
        }
        MGF1ParameterSpec mgf1Spec = (MGF1ParameterSpec) spec.getMGFParameters();
        if (mgf1Spec != null && !(mgf1Spec.getDigestAlgorithm()
                .equals(MGF1ParameterSpec.SHA1.getDigestAlgorithm()))) {
            throw new InvalidAlgorithmParameterException(
                    "Only SHA-1 is supported for MGF1 in OAEP");
        }
        PSource.PSpecified specified = (PSource.PSpecified) spec.getPSource();
        if (specified != null
                && !(Arrays.equals(specified.getValue(), PSource.PSpecified.DEFAULT.getValue()))) {
            throw new InvalidAlgorithmParameterException(
                    "Only PSource.PSpecified.DEFAULT is supported for PSource in OAEP");
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        if (mode == null || mode.matches("ECB")) {
            return;
        }
        throw new NoSuchAlgorithmException("Unsupported mode " + mode);
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("OAEPPadding")
                || padding.equalsIgnoreCase("OAEPWithSHA-1AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA1AndMGF1Padding")) {
            this.padding = RSAPadding.OAEPPadding;
        } else {
            if (provider.isFIPS() && !allowNonOAEPFIPS) {
                throw new NoSuchPaddingException("Padding: " + padding + " not supported through FIPS provider");
            } else {
                if (padding.equalsIgnoreCase("NoPadding")) {
                    this.padding = RSAPadding.NoPadding;
                } else if (padding.equalsIgnoreCase("PKCS1Padding")) {
                    this.padding = RSAPadding.PKCS1Padding;
                } else {
                    throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
                }
            }
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inOffset, int inLen) {
        checkCipherInitialized();
        internalUpdate(input, inOffset, inLen);
        return B0;
    }

    @Override
    protected int engineUpdate(byte[] input, int inOffset, int inLen, byte[] output, int outOffset)
            throws ShortBufferException {
        checkCipherInitialized();
        internalUpdate(input, inOffset, inLen);
        return 0;
    }

    private void internalUpdate(byte[] input, int inOffset, int inLen) {
        if (inLen < 0 || inOffset < 0 || (inOffset + inLen) > input.length) {
            throw new IllegalArgumentException("Input range is invalid");
        } else if (msgLength + inLen > msgBuffer.capacity()) {
            msgLength = msgBuffer.capacity() + 1;
        } else {
            msgBuffer.put(input, inOffset, inLen);
            this.msgLength += inLen;
        }
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }
        if (encoded.length > msgBuffer.capacity()) {
            throw new InvalidKeyException("Key is too long for wrapping");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        checkCipherInitialized();

        if (wrappedKey.length > msgBuffer.capacity()) {
            throw new InvalidKeyException("Key is too long for unwrapping");
        }

        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return ConstructKeys.constructKey(provider, encoded, algorithm, type);
        } catch (BadPaddingException e) {
            // should not occur
            throw new InvalidKeyException("Unwrapping failed", e);
        } catch (IllegalBlockSizeException e) {
            // should not occur, handled with length check above
            throw new InvalidKeyException("Unwrapping failed", e);
        }
    }

    private int oaepInputLimit() throws Exception {
        try {
            int digestLength = 20; // sha-1 digest length
            return rsaCipher.getOutputSize() - (2 * digestLength) - 2;
        } catch (Exception e) {
            throw provider.providerException("Unable to get input limit", e);
        }
    }

    private int pkcs1InputLimit() throws Exception {
        try {
            return rsaCipher.getOutputSize() - 11;
        } catch (Exception e) {
            throw provider.providerException("Unable to get input limit", e);
        }
    }

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }
}
