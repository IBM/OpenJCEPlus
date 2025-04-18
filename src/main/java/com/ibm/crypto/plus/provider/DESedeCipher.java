/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.Padding;
import com.ibm.crypto.plus.provider.ock.SymmetricCipher;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public final class DESedeCipher extends CipherSpi implements DESConstants {

    private OpenJCEPlusProvider provider = null;
    private SymmetricCipher symmetricCipher = null;
    private String mode = "ECB";
    private Padding padding = Padding.PKCS5Padding;
    private byte[] iv = null;
    private boolean encrypting = true;
    private boolean initialized = false;
    private SecureRandom cryptoRandom = null;

    public DESedeCipher(OpenJCEPlusProvider provider) {

        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }

        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];

            int outputLen = symmetricCipher.doFinal(input, inputOffset, inputLen, output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkCipherInitialized();

        try {
            return symmetricCipher.doFinal(input, inputOffset, inputLen, output, outputOffset);
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return DES_BLOCK_SIZE;
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (encoded.length != 24) {
            throw new InvalidKeyException("Invalid key length: " + encoded.length + " bytes");
        }
        return 168;
    }

    @Override
    protected byte[] engineGetIV() {
        return (this.iv == null) ? null : this.iv.clone();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        try {
            return symmetricCipher.getOutputSize(inputLen);
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        AlgorithmParameters params = null;

        if (this.iv != null) {
            IvParameterSpec ivSpec = new IvParameterSpec(this.iv);
            try {
                params = AlgorithmParameters.getInstance("DESede", provider);
                params.init(ivSpec);
            } catch (NoSuchAlgorithmException nsae) {
                throw new ProviderException(
                        "Cannot find DESede AlgorithmParameters implementation in "
                                + provider.getName() + " provider");
            } catch (InvalidParameterSpecException ipse) {
                // should never happen
                throw new ProviderException(ivSpec.getClass() + " not supported");
            }
        }

        return params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (mode.equals("ECB")) {
            internalInit(opmode, key, null);
            return;
        }

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new InvalidKeyException("Parameters missing");
        }

        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(random);
        }

        byte[] generatedIv = new byte[DES_BLOCK_SIZE];
        cryptoRandom.nextBytes(generatedIv);

        internalInit(opmode, key, generatedIv);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            if (params instanceof IvParameterSpec) {
                byte[] iv = ((IvParameterSpec) params).getIV();
                if (iv.length != DES_BLOCK_SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "IV must be " + DES_BLOCK_SIZE + " bytes");
                }
                internalInit(opmode, key, iv);
            } else {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec ivSpec = null;

        if (params != null) {
            try {
                ivSpec = params.getParameterSpec(IvParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException("Wrong parameter type: IV expected");
            }
        }

        engineInit(opmode, key, ivSpec, random);
    }

    private void internalInit(int opmode, Key key, byte[] iv) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("DESede"))) {
            throw new InvalidKeyException("Wrong algorithm: DESede required");
        }

        if (!(key.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (!isKeySizeValid(rawKey.length)) {
            throw new InvalidKeyException("Invalid DESede key length: " + rawKey.length + " bytes");
        }

        boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE);
        // if (isEncrypt && provider.isFIPS()) {
        // throw new ProviderException("DESede encrypt is not supported in FIPS
        // mode");
        // }

        try {
            if (symmetricCipher == null) {
                symmetricCipher = SymmetricCipher.getInstanceDESede(provider.getOCKContext(), mode,
                        padding);
            }

            if (isEncrypt) {
                symmetricCipher.initCipherEncrypt(rawKey, iv);
            } else {
                symmetricCipher.initCipherDecrypt(rawKey, iv);
            }

            this.iv = iv;
            this.encrypting = isEncrypt;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        String modeUpperCase = mode.toUpperCase();
        if (modeUpperCase.equals("ECB") || modeUpperCase.equals("CBC")/*
                                                                         * || modeUpperCase.equals("OFB") ||
                                                                         * modeUpperCase.equals("CFB")
                                                                         */) {
            this.mode = modeUpperCase;
        } /*
             * else if (modeUpperCase.equals("CFB64")) { this.mode = "CFB"; }
             */ else {
            throw new NoSuchAlgorithmException("Cipher mode: " + mode + " not found");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = Padding.NoPadding;
        } else if (padding.equalsIgnoreCase("PKCS5Padding")) {
            this.padding = Padding.PKCS5Padding;
        } else {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        checkCipherInitialized();

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];

            int outputLen = symmetricCipher.update(input, inputOffset, inputLen, output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else {
                return output;
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        checkCipherInitialized();

        try {
            return symmetricCipher.update(input, inputOffset, inputLen, output, outputOffset);
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        checkCipherInitialized();

        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
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

    private void checkCipherInitialized() throws IllegalStateException {
        if (!this.initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    static final boolean isKeySizeValid(int len) {
        return len == 24 ? true : false;
    }
}
