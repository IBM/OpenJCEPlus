/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKException;
import com.ibm.crypto.plus.provider.ock.Padding;
import com.ibm.crypto.plus.provider.ock.Poly1305Cipher;
import java.io.IOException;
import java.nio.ByteBuffer;
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
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import sun.security.util.DerValue;

public final class ChaCha20Poly1305Cipher extends CipherSpi
        implements ChaCha20Constants, Poly1305Constants {

    private static final String OCK_CHACHA20_POLY1305 = "chacha20-poly1305";
    private Poly1305Cipher poly1305Cipher = null;
    private static final byte[] emptyAAD = new byte[0];
    private OpenJCEPlusProvider provider = null;
    private Padding padding = Padding.NoPadding;
    private byte[] keyBytes = null;
    private byte[] nonceBytes = null;
    private byte[] authData = null;
    private boolean encrypting = false;
    private boolean initialized = false;
    private boolean aadDone = false;
    //final static String debPrefix = "ChaCha20Poly1305 ";

    public ChaCha20Poly1305Cipher(OpenJCEPlusProvider provider) {
        if (!OpenJCEPlusProvider.verifySelfIntegrity(this)) {
            throw new SecurityException("Integrity check failed for: " + provider.getName());
        }
        this.provider = provider;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        //final String methodName = "engineDoFinal ";

        checkCipherInitialized();

        this.aadDone = true;

        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];
            int outputLen = poly1305Cipher.doFinal(input, inputOffset, inputLen, output, 0);
            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }
                return out;
            } else if (outputLen > output.length) {
                throw new IllegalBlockSizeException("OUTPUT LENGTH FROM OCK > ALLOCATED");
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
        } catch (IllegalArgumentException ock_iae) {
            IllegalArgumentException iae = new IllegalArgumentException(ock_iae.getMessage());
            provider.setOCKExceptionCause(iae, ock_iae);
            throw iae;
        } catch (OCKException ockException) {
            if (!encrypting) {
                throw new AEADBadTagException("Tag mismatch");
            } else {
                throw provider.providerException("Failure in engineDoFinal", ockException);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            resetVars();
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        //final String methodName = "engineDoFinal ";

        checkCipherInitialized();

        this.aadDone = true;

        try {
            int retvalue = poly1305Cipher.doFinal(input, inputOffset, inputLen, output,
                    outputOffset);
            return retvalue;
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
        } catch (IllegalArgumentException ock_iae) {
            IllegalArgumentException iae = new IllegalArgumentException(ock_iae.getMessage());
            provider.setOCKExceptionCause(iae, ock_iae);
            throw iae;
        } catch (OCKException ockException) {
            if (!encrypting) {
                throw new AEADBadTagException("Tag mismatch");
            } else {
                throw provider.providerException("Failure in engineDoFinal", ockException);
            }
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        } finally {
            resetVars();
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return ChaCha20_BLOCK_SIZE;
    }

    @Override
    protected byte[] engineGetIV() {
        return (this.nonceBytes == null) ? null : this.nonceBytes.clone();
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        //final String methodName = "engineGetKeySize";
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (encoded.length != ChaCha20_KEY_SIZE) {
            throw new InvalidKeyException("Key must be " + ChaCha20_KEY_SIZE + " bytes");
        }

        return encoded.length << 3;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        //final String methodName = "engineGetoutputSize";
        try {
            return poly1305Cipher.getOutputSize(inputLen, encrypting, Poly1305_TAG_SIZE);
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        //final String methodName = "engineGetParameters";
        AlgorithmParameters chaCha20Poly1305Params = null;
        byte[] nonce = engineGetIV();

        if (nonce != null) {

            IvParameterSpec chaCha20Poly1305ParamSpec = new IvParameterSpec(nonce);

            try {
                chaCha20Poly1305Params = AlgorithmParameters.getInstance("ChaCha20-Poly1305");
                chaCha20Poly1305Params.init(chaCha20Poly1305ParamSpec);
            } catch (NoSuchAlgorithmException nsae) {
                // should never happen
                throw new ProviderException(nsae.getMessage());
            } catch (InvalidParameterSpecException ipse) {
                // should never happen
                throw new ProviderException(ipse.getMessage());
            }
        } else {
            // Generate random nonce in pre-init state without attaching to the object
            byte[] nonceData = generateRandomNonce(null);
            try {
                // Format as [octet[12-byte nonce]]
                chaCha20Poly1305Params = AlgorithmParameters.getInstance("ChaCha20-Poly1305");
                chaCha20Poly1305Params
                        .init((new DerValue(DerValue.tag_OctetString, nonceData).toByteArray()));
            } catch (NoSuchAlgorithmException | IOException exc) {
                throw new RuntimeException(exc);
            }
        }

        return chaCha20Poly1305Params;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        //final String methodName = "engineInit";
        this.aadDone = false;
        this.initialized = false;

        if (opmode == Cipher.DECRYPT_MODE) {
            throw new InvalidKeyException("Parameters missing");
        }

        internalInit(opmode, key, generateRandomNonce(random));
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        //final String methodName = "engineInit";
        this.aadDone = false;
        this.initialized = false;

        if (params == null) {
            engineInit(opmode, key, random);
        } else {
            if (params instanceof IvParameterSpec) {
                byte[] nonce = ((IvParameterSpec) params).getIV();
                if (nonce.length != ChaCha20_NONCE_SIZE) {
                    throw new InvalidAlgorithmParameterException(
                            "Nonce must be " + ChaCha20_NONCE_SIZE + " bytes");
                }
                internalInit(opmode, key, nonce);
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter type: IvParameterSpec expected");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        //final String methodName = "engineInit ";

        this.initialized = false;
        this.aadDone = false;

        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }
        byte[] newNonce;
        String paramAlg = params.getAlgorithm();
        if (!paramAlg.equalsIgnoreCase("ChaCha20-Poly1305")) {
            throw new InvalidAlgorithmParameterException("Invalid parameter type: " + paramAlg);
        }
        try {
            DerValue dv = new DerValue(params.getEncoded());
            newNonce = dv.getOctetString();
            if (newNonce.length != 12) {
                throw new InvalidAlgorithmParameterException(
                        "ChaCha20-Poly1305 nonce must be " + "12 bytes in length");
            }
        } catch (IOException ioe) {
            throw new InvalidAlgorithmParameterException(ioe);
        }
        internalInit(opmode, key, newNonce);
    }

    private void internalInit(int opmode, Key newKey, byte[] newNonceBytes)
            throws InvalidKeyException {
        //final String methodName = "internalInit ";

        if ((opmode == Cipher.WRAP_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
        } else if ((opmode != Cipher.ENCRYPT_MODE) && (opmode != Cipher.DECRYPT_MODE)) {
            throw new InvalidKeyException("Unknown opmode: " + opmode);
        }

        if (newKey == null) {
            throw new InvalidKeyException("Key missing");
        }

        // NOTE: By definition, both the Oracle and IBM "ChaCha20" and "ChaCha20-Poly1305" cipher implementations use the "ChaCha20" SecretKey 
        // algorithm name...  "ChaCha20-Poly1305" was added here to satisfy the Oracle TLS1.3 implementation, which generates 
        // SecretKeys with that name "under the covers" instead of using the KeyGenerator framework API.

        if (!(((newKey.getAlgorithm().equalsIgnoreCase("ChaCha20")))
                || ((newKey.getAlgorithm().equalsIgnoreCase("ChaCha20-Poly1305"))))) {
            throw new InvalidKeyException("Wrong algorithm: ChaCha20 required");
        }

        if (!(newKey.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] newKeyBytes = newKey.getEncoded();
        if (newKeyBytes == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (newKeyBytes.length != ChaCha20_KEY_SIZE) {
            throw new InvalidKeyException("Key must be " + ChaCha20_KEY_SIZE + " bytes");
        }

        this.encrypting = (opmode == Cipher.ENCRYPT_MODE);

        if (this.encrypting) {
            checkKeyAndNonce(newKeyBytes, newNonceBytes);
        }

        try {
            if (poly1305Cipher == null) {
                poly1305Cipher = Poly1305Cipher.getInstance(provider.getOCKContext(),
                        OCK_CHACHA20_POLY1305, padding);
            }

            if (this.encrypting) {
                poly1305Cipher.initCipherEncrypt(newKeyBytes, newNonceBytes);
            } else {
                poly1305Cipher.initCipherDecrypt(newKeyBytes, newNonceBytes);
            }
            this.keyBytes = newKeyBytes;
            this.nonceBytes = newNonceBytes;
            this.initialized = true;
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }
    }

    private void checkKeyAndNonce(byte[] newKeyBytes, byte[] newNonce) throws InvalidKeyException {
        //final String methodName = "checkKeyAndNonce";

        // A new initialization must have either a different key or nonce
        // so the starting state for each block is not the same as the
        // previous initialization.

        if (MessageDigest.isEqual(newKeyBytes, this.keyBytes)
                && MessageDigest.isEqual(newNonce, this.nonceBytes)) {
            throw new InvalidKeyException("Matching key and nonce from previous initialization");
        }
    }

    private boolean checkKeyAndNonce(byte[] curKeyBytes, byte[] curNonce, byte[] lastKeyBytes,
            byte[] lastNonce) {

        // A new initialization must have either a different key or nonce
        // so the starting state for each block is not the same as the
        // previous initialization.
        boolean equalFlag = false;

        if (MessageDigest.isEqual(curKeyBytes, lastKeyBytes)
                && MessageDigest.isEqual(curNonce, lastNonce)) {
            equalFlag = true;
        }

        return equalFlag;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        //final String methodName = "engineSetMode";
        if (mode.equalsIgnoreCase("None") == false) {
            throw new NoSuchAlgorithmException("Mode must be None");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        //final String methodName = "engineSetPadding";
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = Padding.NoPadding;
        } else {
            throw new NoSuchPaddingException("Padding: " + padding + " not implemented");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

        //final String methodName = "engineUpdate ";
        checkCipherInitialized();

        this.aadDone = true;

        try {

            // For update output size = input size...
            byte[] output = new byte[inputLen];

            int outputLen = poly1305Cipher.update(input, inputOffset, inputLen, output, 0);
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

        //final String methodName = "engineUpdate ";
        checkCipherInitialized();

        this.aadDone = true;

        try {
            int retvalue = poly1305Cipher.update(input, inputOffset, inputLen, output,
                    outputOffset);
            return retvalue;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoUpdate", e);
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {

        //final String methodName = "engineUpdateAAD ";

        checkCipherInitialized();

        if (this.aadDone) {
            //OCKDebug.Msg(debPrefix, methodName, "engineUpdateAAD Failure: IllegalStateException AAD update already done");
            throw new IllegalStateException("AAD update already done");
        }
        this.authData = new byte[len];
        System.arraycopy(src, offset, authData, 0, len);

        try {
            poly1305Cipher.update(authData, 0, authData.length, null, 0);
            this.aadDone = true;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdateAAD", e);
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {

        //final String methodName = "engineUpdateAAD ";

        checkCipherInitialized();

        if (this.aadDone) {
            throw new IllegalStateException("AAD update already done");
        }

        this.authData = /*new byte[src.remaining()];*/ new byte[src.capacity()];
        src.get(authData, 0, authData.length);
        try {
            poly1305Cipher.update(authData, 0, authData.length, null, 0);
            this.aadDone = true;
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdateAAD", e);
        }

    }

    // see JCE spec
    protected byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException {
        throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
    }

    // see JCE spec
    protected Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
            throws InvalidKeyException, NoSuchAlgorithmException {
        throw new UnsupportedOperationException("WRAP_MODE and UNWRAP_MODE are not supported");
    }

    private void checkCipherInitialized() throws IllegalStateException {
        //final String methodName = "checkCipherInitialized";
        if (!this.initialized) {
            //OCKDebug.Msg(debPrefix, methodName, "checkCipherInitialized Failure: IllegalStateException");
            throw new IllegalStateException("Cipher has not been initialized");
        }
    }

    // Reset class variables.
    private void resetVars() {
        this.initialized = (!this.encrypting); // force re-initialization only when encrypting
        this.aadDone = false;
    }

    private byte[] generateRandomNonce(SecureRandom random) {
        SecureRandom rand = (random != null) ? random : new SecureRandom();
        SecureRandom cryptoRandom = provider.getSecureRandom(rand);
        byte[] generatedNonce = new byte[ChaCha20_NONCE_SIZE];
        cryptoRandom.nextBytes(generatedNonce);

        return generatedNonce;
    }
}
