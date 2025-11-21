/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.CCMCipher;
import com.ibm.crypto.plus.provider.ock.OCKContext;
import ibm.security.internal.spec.CCMParameterSpec;
import java.math.BigInteger;
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
import sun.security.util.Debug;

public final class AESCCMCipher extends CipherSpi implements AESConstants, CCMConstants {

    String debPrefix = "AESCCMCipher ";

    private OpenJCEPlusProvider provider = null;
    private OCKContext ockContext = null;
    private boolean encrypting = true;
    private boolean initialized = false;
    private int tagLenInBytes = DEFAULT_AES_CCM_TAG_LENGTH / 8;

    private BigInteger generatedIVCtrField = null;
    private byte[] generatedIVDevField = null;
    private boolean generateIV = false;
    private SecureRandom cryptoRandom = null;

    private byte[] IV = null;
    private byte[] newIV = null;
    private byte[] Key = null;
    private byte[] authData = null;
    private boolean updateCalled = false;
    // User enabled debugging
    private static Debug debug = Debug.getInstance(OpenJCEPlusProvider.DEBUG_VALUE);

    /*
     * index of the content size left in the buffer
     */

    private int buffered = 0;
    /*
     * block size of cipher in bytes
     */

    private int blockSize = AES_BLOCK_SIZE;

    /*
     * internal buffer
     */

    private byte[] buffer = null;

    /*
     * minimum number of bytes in the buffer required for
     * FeedbackCipher.encryptFinal()/decryptFinal() call.
     * update() must buffer this many bytes before starting
     * to encrypt/decrypt data.
     * currently, only the following cases have non-zero values:
     *
     * 1) CCM mode + decryption - due to its trailing tag bytes
     */
    private int minBytes = 0;


    /*
     * variables used for performing the CCM (key+iv) uniqueness check.
     * To use CCM mode safely, the cipher object must be re-initialized
     * with a different combination of key + iv values for each
     * ENCRYPTION operation. However, checking all past key + iv values
     * isn't feasible. Thus, we only do a per-instance check of the
     * key + iv values used in previous encryption.
     * For decryption operations, no checking is necessary.
     */
    private boolean requireReinit = false;
    private byte[] lastEncKey = null;
    private byte[] lastEncIv = null;


    public AESCCMCipher(OpenJCEPlusProvider provider) {
        this.provider = provider;
        try {
            ockContext = provider.getOCKContext();
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize cipher context", e);
        }
        buffer = new byte[AES_BLOCK_SIZE * 2];

        this.provider.registerCleanable(this, cleanOCKResources(Key, ockContext));
    }


    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName = "byte[] enginedoFinal";

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();

        try {
            byte[] output;

            if (encrypting) {
                output = new byte[inputLen + tagLenInBytes];
            } else { // decrypting
                output = new byte[inputLen - tagLenInBytes];
            }

            int outputLen = engineDoFinal(input, inputOffset, inputLen, output, 0);

            if (outputLen < output.length) {
                byte[] out = Arrays.copyOfRange(output, 0, outputLen);
                if (!encrypting) {
                    Arrays.fill(output, 0, outputLen, (byte) 0x00);
                }

                return out;
            } else {
                return output;
            }
        } catch (ShortBufferException e) {
            /*
             * this exception shouldn't happen because the output buffer is allocated here
             * but engineDoFinal(..) is declared to be able to throw it since it also
             * handles user provided output buffers
             */
            // OCKDebug.Msg(debPrefix, methodName, "OCKException seen");
            if (!encrypting) {
                AEADBadTagException abte = new AEADBadTagException(
                        "Unable to perform engine doFinal; Possibly a bad tag or bad padding or illegalBlockSize");
                provider.setOCKExceptionCause(abte, e);
                throw abte;
            } else {
                throw provider.providerException("unable to perform to engineDoFinal ", e);
            }
        } catch (IllegalStateException ex) {
            requireReinit = true;
            throw ex;
        }

    }


    @Override
    protected int engineDoFinal(ByteBuffer inputByteBuffer, ByteBuffer outputByteBuffer)
            throws IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName = "byte[] enginedoFinal";

        if (inputByteBuffer == null) {
            throw new IllegalArgumentException("The input ByteBuffer argument is null.");
        }
        if (outputByteBuffer == null) {
            throw new IllegalArgumentException("The output ByteBuffer argument is null.");
        }

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();

        try {
            byte[] output = null;

            if (encrypting) {
                output = new byte[inputByteBuffer.array().length + tagLenInBytes];
            } else { // decrypting
                output = new byte[inputByteBuffer.array().length - tagLenInBytes];
            }

            byte[] input = inputByteBuffer.array();
            int inputLen = input.length;
            int inputOffset = 0;
            int outputLen = engineDoFinal(input, inputOffset, inputLen, output, 0);

            // Copy the data within output into the outputByteBuffer and return the number of bytes copied.
            outputByteBuffer.put(output);
            return outputLen;
        } catch (ShortBufferException e) {
            /*
             * this exception shouldn't happen because the output buffer is allocated here
             * but engineDoFinal(..) is declared to be able to throw it since it also
             * handles user provided output buffers
             */
            // OCKDebug.Msg(debPrefix, methodName, "OCKException seen");
            if (!encrypting) {
                AEADBadTagException abte = new AEADBadTagException(
                        "Uanble to perform engine doFinal; Possibly a bad tag or bad padding or illegalBlockSize");
                provider.setOCKExceptionCause(abte, e);
                throw abte;
            } else {
                throw provider.providerException("unable to perform to engineDoFinal ", e);
            }
        } catch (IllegalStateException ex) {
            requireReinit = true;
            throw ex;
        }
    }


    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        //final String methodName = "engineDoFinal";

        // Force the doFinal caller to call getOutputSize( ) and add the length of the doFinal data to it.
        if (encrypting) {
            if ((output.length - outputOffset) < (input.length + tagLenInBytes)) {
                throw new ShortBufferException(
                        "The output buffer is too small to hold the encryption result.");
            }
        } else { // decrypting
            if ((output.length - outputOffset) < (input.length - tagLenInBytes)) {
                throw new ShortBufferException(
                        "The output buffer is too small to hold the decryption result.");
            }
        }

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();

        try {
            if (encrypting) {
                if ((output == null) || (output.length - outputOffset < inputLen + tagLenInBytes)) {
                    throw new ShortBufferException(
                            "Output buffer is not long enough to contain ciphertext and tag.");
                }

                /*
                 * switch to the newly generated IV only at this point, need to keep the old IV
                 * around since getIV() might be called up to this point
                 */
                if (generateIV && newIV != null) {
                    IV = newIV.clone();
                    newIV = null;
                }

                int ret = CCMCipher.doCCMFinal_Encrypt(ockContext, Key, IV, tagLenInBytes, input,
                        inputOffset, inputLen, output, outputOffset, authData);
                authData = null; // Before returning from doFinal(), restore AAD to uninitialized state

                if (generateIV) {
                    /*
                     * Generate the next internal AES-CCM initialization vector
                     */
                    newIV = generateInternalIV().clone();
                }
                return ret;

            } else { // else decrypting

                if ((input == null) || (input.length == 0)) { // If this doFinal( ) carries no data to be encrypted
                    return 0;
                }

                if (inputLen < tagLenInBytes) {
                    throw new AEADBadTagException("Input too short - need tag");
                }

                if ((output == null)
                        || ((output.length - outputOffset) < (inputLen - tagLenInBytes))) {
                    throw new ShortBufferException("Output buffer too small");
                }

                int ret = CCMCipher.doCCMFinal_Decrypt(ockContext, Key, IV, tagLenInBytes, input,
                        inputOffset, inputLen, output, outputOffset, authData);
                authData = null; // Before returning from doFinal(), restore AAD to uninitialized state
                return ret;
            }
        } catch (AEADBadTagException e) {
            AEADBadTagException abte = new AEADBadTagException(e.getMessage());
            provider.setOCKExceptionCause(abte, e);
            requireReinit = true;
            throw abte;
        } catch (BadPaddingException ock_bpe) {
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            requireReinit = true;
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            requireReinit = true;
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (com.ibm.crypto.plus.provider.ock.OCKException ock_excp) {
            requireReinit = true;
            AEADBadTagException tagexcp = new AEADBadTagException(ock_excp.getMessage());
            provider.setOCKExceptionCause(tagexcp, ock_excp);
            throw tagexcp;

        } catch (Exception e) {
            requireReinit = true;
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }


    @Override
    protected int engineGetBlockSize() {
        return AES_BLOCK_SIZE;
    }


    /**
     * Returns the initialization vector (IV) in a new buffer.
     *
     * <p>This is useful in the case where a random IV has been created
     * (see <a href = "#init">init</a>),
     * or in the context of password-based encryption or
     * decryption, where the IV is derived from a user-provided password.
     *
     * @return the initialization vector in a new buffer, or null if the
     * underlying algorithm does not use an IV, or if the IV has not yet
     * been set.
     */
    @Override
    protected byte[] engineGetIV() {
        return (IV != null) ? IV.clone() : null;
    }


    /**
     * Returns the length in bytes that an output buffer would need to be in
     * order to hold the result of the next <code>update</code> or
     * <code>doFinal</code> operation, given the input length
     * <code>inputLen</code> (in bytes).
     *
     * <p>This call takes into account any unprocessed (buffered) data from a
     * previous <code>update</code> call, padding, and AEAD tagging.
     *
     * <p>The actual output length of the next <code>update</code> or
     * <code>doFinal</code> call may be smaller than the length returned by
     * this method.
     *
     * @param inputLen the input length (in bytes)
     *
     * @return the required output buffer size (in bytes)
     */
    int getOutputSize(int inputLen) {
        // estimate based on the maximum
        return engineGetOutputSize(inputLen);
    }


    @Override
    protected int engineGetOutputSize(int inputLen) {
        if (encrypting) {
            return inputLen + tagLenInBytes;
        } else {
            return (inputLen < tagLenInBytes) ? 0 : inputLen - tagLenInBytes;
        }
    }


    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (IV == null)
            return null;
        CCMParameterSpec ccmps = new CCMParameterSpec(DEFAULT_AES_CCM_TAG_LENGTH, engineGetIV());
        AlgorithmParameters ccmParams;
        try {
            ccmParams = AlgorithmParameters.getInstance("CCM");
            ccmParams.init(ccmps);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            throw new ProviderException(nsae.getMessage());
        } catch (InvalidParameterSpecException ipse) {
            // should never happen
            throw new ProviderException(ipse.getMessage());
        }
        return ccmParams;
    }


    // Ordinarily, a CCMParameterSpec or CCMParameters object would supply the
    // following attributes to an engineInit( ) method:
    //     tLen - the authentication tag length (in bits)
    //     src  - the IV source buffer
    // however neither are supplied here.
    // With this init method, the "IV" is generated internally, and the
    // "authentication tag length (in bits)" is the default value defined for this class.
    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            encrypting = false;
            /* Decryption requires explicit algorithm parameters */
            throw new InvalidKeyException("Decryption requires explicit algorithm parameters");
            // throw new InvalidAlgorithmParameterException ("Decryption requires explicit
            // algorithm parameters");
        } else {
            encrypting = true;
            generateIV = true; // Automatically generate an IV if "encrypt mode" or "wrap mode"
                               // because no CCMParameterSpec object or CCMParameters object was
                               // specified on this engineInit().
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }

        /*
         * Generate the first internal AES-CCM initialization vector
         */
        byte[] tempIV = generateInternalIV();

        if (encrypting) {
            byte[] keyBytes = key.getEncoded().clone();
            requireReinit = Arrays.equals(tempIV, lastEncIv)
                    && MessageDigest.isEqual(keyBytes, lastEncKey);
            if (requireReinit) {
                throw new ProviderException("Cannot reuse iv for CCM encryption");
            }
            lastEncIv = tempIV;
            lastEncKey = keyBytes;
        } else {
            requireReinit = false;
        }

        internalInit(opmode, key, tempIV);
        requireReinit = false;
    }



    // The CCMParameterSpec will carry
    //     int tLen   - the authentication tag length (in bits)
    //     byte[] src - the initialization vector (IV)
    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            encrypting = false;
        } else {
            encrypting = true;
            generateIV = false; // Do not generate an IV automatically, because
                                // an IV (aka nonce) should have been speficied within
                                // the CCMParameterSpec argument.
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        if (params != null) { // if we have a ParameterSpec, check to see if it
                              // is CCMParameterSpec
            if (params instanceof CCMParameterSpec) {
                byte[] ivTemp = ((CCMParameterSpec) params).getIV();
                if (ivTemp.length == 0) {
                    if (encrypting) {
                        tagLenInBytes = ((CCMParameterSpec) params).getTLen() / 8;

                        byte[] newIV = generateInternalIV();
                        byte[] keyBytes = key.getEncoded().clone();

                        requireReinit = Arrays.equals(newIV, lastEncIv)
                                && MessageDigest.isEqual(keyBytes, lastEncKey);
                        if (requireReinit) {
                            throw new InvalidAlgorithmParameterException(
                                    "Cannot reuse iv for CCM encryption");
                        }
                        lastEncIv = newIV.clone();
                        lastEncKey = keyBytes;
                        // ibuffer = null;
                        // minBytes = 0;
                        internalInit(opmode, key, newIV);
                    } else {
                        /* Decryption requires explicit algorithm parameters */
                        throw new InvalidAlgorithmParameterException(
                                "Decryption requires explicit algorithm parameters");
                    }
                } else {
                    tagLenInBytes = ((CCMParameterSpec) params).getTLen() / 8;

                    if (encrypting) {
                        byte[] keyBytes = key.getEncoded().clone();
                        requireReinit = Arrays.equals(ivTemp, lastEncIv)
                                && MessageDigest.isEqual(keyBytes, lastEncKey);
                        if (requireReinit) {
                            throw new InvalidAlgorithmParameterException(
                                    "Cannot reuse iv for CCM encryption");
                        }
                        lastEncIv = ivTemp.clone();
                        lastEncKey = keyBytes;
                        // ibuffer = null;
                    } else {
                        requireReinit = false;
                        // ibuffer = new ByteArrayOutputStream();
                        // minBytes = tagLenInBytes;
                    }

                    internalInit(opmode, key, ((CCMParameterSpec) params).getIV().clone());
                }
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter " + "type: CCM " + "expected");
            }
        } else {
            if (encrypting) {
                /* Must generate the algorithm parameters internally */
                engineInit(opmode, key, random);
            } else {
                /* Decryption requires explicit algorithm parameters */
                throw new InvalidAlgorithmParameterException(
                        "Decryption requires explicit algorithm parameters");
            }
        }
    }


    // The CCMParameters can be converted to a CCMParameterSpec which will carry
    //     int tLen   - the authentication tag length (in bits)
    //     byte[] src - the initialization vector (IV)
    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            encrypting = false;
        } else {
            encrypting = true;
            generateIV = false; // Do not generate an IV automatically, because
                                // an IV (aka nonce) should have been specified within
                                // the CCMParameters argument.
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }

        if (params != null) {
            CCMParameterSpec ivSpec = null;
            try {
                ivSpec = params.getParameterSpec(CCMParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter " + "type: CCM " + "expected");
            }
            engineInit(opmode, key, ivSpec, random);
        } else {
            if (encrypting) {
                /* Must generate the algorithm parameters internally */
                engineInit(opmode, key, random);
            } else {
                /* Decryption requires explicit algorithm parameters */
                throw new InvalidAlgorithmParameterException(
                        "Decryption requires explicit algorithm parameters");
            }
        }
    }


    private void internalInit(int opmode, Key key, byte[] iv) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        if (!(key.getAlgorithm().equalsIgnoreCase("AES"))) {
            throw new InvalidKeyException("Wrong algorithm: AES required");
        }

        if (!(key.getFormat().equalsIgnoreCase("RAW"))) {
            throw new InvalidKeyException("Wrong format: RAW bytes needed");
        }

        byte[] rawKey = key.getEncoded();
        if (rawKey == null) {
            throw new InvalidKeyException("RAW bytes missing");
        }

        if (!AESUtils.isKeySizeValid(rawKey.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + rawKey.length + " bytes");
        }

        try {
            boolean isEncrypt = (opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.WRAP_MODE);
            this.newIV = null;
            this.Key = rawKey.clone();
            this.IV = iv.clone();
            this.encrypting = isEncrypt;
            this.initialized = true;
            this.authData = null; // Before returning from internalInit(), restore AAD to uninitialized state
            this.updateCalled = false;
            this.buffered = 0;
            Arrays.fill(buffer, (byte) 0x0);
        } catch (Exception e) {
            throw provider.providerException("Failed to init cipher", e);
        }
    }


    private byte[] generateInternalIV() throws IllegalStateException {
        byte[] generatedIV = new byte[DEFAULT_AES_CCM_IV_LENGTH];
        if (cryptoRandom == null) {
            cryptoRandom = provider.getSecureRandom(null);
        }
        cryptoRandom.nextBytes(generatedIV);
        return generatedIV;
    }


    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        return;
    }


    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        return;
    }


    /**
     * Returns the key size of the given key object.
     *
     * @param key
     *            the key object.
     *
     * @return the key size of the given key object.
     *
     * @exception InvalidKeyException
     *                if <code>key</code> is invalid.
     */
    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key missing");
        }

        byte[] encoded = key.getEncoded();
        if (!AESUtils.isKeySizeValid(encoded.length)) {
            throw new InvalidKeyException("Invalid AES key length: " + encoded.length + " bytes");
        }
        return encoded.length << 3;
    }


    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        //final String methodName = "engineUpdateAAD";
        // OCKDebug.Msg(debPrefix, methodName, "engingeUpdateAAD called with byte[] +
        // updateCalled=" + updateCalled);
        // String.valueOf(encrypting) + " inputOffset=" + inputOffset + " inputLen=" +
        // inputLen + " outputOffset=" + outputOffset + " output.length=" +
        // output.length);

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();
        if (updateCalled) {
            throw new IllegalStateException(
                    "AAD must be supplied before encryption/decryption starts");
        }

        if (this.authData == null) {
            this.authData = new byte[len];
            System.arraycopy(src, offset, authData, 0, len);
        } else {
            byte[] tempAuthData = new byte[this.authData.length + len];
            System.arraycopy(this.authData, 0, tempAuthData, 0, this.authData.length);
            System.arraycopy(src, offset, tempAuthData, this.authData.length, len);
            this.authData = tempAuthData;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        //final String methodName = "engineUpdateAAD";
        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        // OCKDebug.Msg(debPrefix, methodName, "engineUpdateAAD called with ByteBuffer"
        // + src);
        checkReinit();
        if (updateCalled) {
            throw new IllegalStateException(
                    "AAD must be supplied before encryption/decryption starts");
        }

        if (this.authData == null) {
            this.authData = new byte[src.remaining()];
            src.get(this.authData, 0, this.authData.length);
        } else { // else this.authData != null
            byte[] tempAuthData = new byte[this.authData.length + src.remaining()];
            System.arraycopy(this.authData, 0, tempAuthData, 0, this.authData.length);
            src.get(tempAuthData, this.authData.length, src.remaining());
            this.authData = tempAuthData;
        }
    }


    /**
     * Returns the mode of this cipher.
     *
     * @return the parsed cipher mode
     */
    int getMode() {
        return (encrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    private void checkReinit() {
        if (requireReinit) {
            throw new IllegalStateException(
                    "Must use either different key or iv for CCM encryption");
        }
    }


    protected final byte[] engineUpdate(byte[] input) {
        throw new ProviderException(
                "engineUpdate is not supported for AESCCM.  Only engineDoFinal is supported.");
    }


    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        throw new ProviderException(
                "engineUpdate is not supported for AESCCM.  Only engineDoFinal is supported.");
    }


    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output)
            throws ShortBufferException {
        throw new ProviderException(
                "engineUpdate is not supported for AESCCM.  Only engineDoFinal is supported.");
    }


    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        throw new ProviderException(
                "engineUpdate is not supported for AESCCM.  Only engineDoFinal is supported.");
    }


    protected int engineUpdate(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        throw new ProviderException(
                "engineUpdate is not supported for AESCCM.  Only engineDoFinal is supported.");
    }

    private Runnable cleanOCKResources(byte[] Key, OCKContext ockContext) {
        return() -> {
            try {
                if (ockContext != null) {
                    CCMCipher.doCCM_cleanup(ockContext);
                }
                if (Key != null) {
                    Arrays.fill(Key, (byte) 0x00);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }

} // End of class
