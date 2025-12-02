/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.GCMCipher;
import com.ibm.crypto.plus.provider.ock.OCKContext;
import com.ibm.crypto.plus.provider.ock.OCKException;
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
import javax.crypto.spec.GCMParameterSpec;

public final class AESGCMCipher extends CipherSpi implements AESConstants, GCMConstants {

    String debPrefix = "AESGCMCipher ";


    private OpenJCEPlusProvider provider = null;
    private OCKContext ockContext = null;
    private boolean encrypting = true;
    private boolean initialized = false;
    private int tagLenInBytes = DEFAULT_TAG_LENGTH / 8;

    private BigInteger generatedIVCtrField = null;
    private byte[] generatedIVDevField = null;
    private boolean generateIV = false;
    private SecureRandom cryptoRandom = null;

    private byte[] IV = null;
    private byte[] newIV = null;
    private PrimitiveWrapper.ByteArray Key = new PrimitiveWrapper.ByteArray(null);
    private byte[] authData = null;
    private boolean updateCalled = false;

    // Java 8 Cipher.class documentation does not require that an cipher.init is
    // called between successive encryption or decryption. However it requires
    // prior IV+ Key cannot be used. Since it is not feasible to maintain a history
    // of previously called IV+Key combination, this implementation checks the
    // previous encryption. The exception to this requirement is when
    // a ShortBufferException was encountered, the Cipher class allows same IV and Key but with a
    // larger buffer.
    // Calling encryption/decryption after a sbe is allowed which allows applications
    // to call failed operation with a larger buffer
    // This implementation deviates from Sun's implementation.

    // Keeps track if a shortBufferException was experienced in last call.
    // Calling encryption/decrytion after a sbe is allowed which allows applications
    // to call failed operation with a larger buffer.
    private boolean sbeInLastFinalEncrypt = false;
    private boolean sbeInLastUpdateEncrypt = false;
    boolean initCalledInEncSeq = false;
    boolean aadDone = false;



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
     * 1) GCM mode + decryption - due to its trailing tag bytes
     */

    private int minBytes = 0;


    /*
     * unit size (number of input bytes that can be processed at a time)
     */

    private int unitBytes = AES_BLOCK_SIZE;



    /*
     * number of bytes needed to make the total input length a multiple
     * of the blocksize (this is used in feedback mode, when the number of
     * input bytes that are processed at a time is different from the block
     * size)
     */
    private int diffBlocksize = AES_BLOCK_SIZE;



    /*
     * variables used for performing the GCM (key+iv) uniqueness check.
     * To use GCM mode safely, the cipher object must be re-initialized
     * with a different combination of key + iv values for each
     * ENCRYPTION operation. However, checking all past key + iv values
     * isn't feasible. Thus, we only do a per-instance check of the
     * key + iv values used in previous encryption.
     * For decryption operations, no checking is necessary.
     */
    private boolean requireReinit = false;
    private byte[] lastEncKey = null;
    private byte[] lastEncIv = null;

    public AESGCMCipher(OpenJCEPlusProvider provider) {
        this.provider = provider;
        try {
            ockContext = provider.getOCKContext();
        } catch (Exception e) {
            throw provider.providerException("Failed to initialize cipher context", e);
        }
        buffer = new byte[AES_BLOCK_SIZE * 2];

        this.provider.registerCleanable(this, cleanOCKResources(Key));
    }


    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException, AEADBadTagException {
        //final String methodName = "byte[] enginedoFinal";

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();
        if (updateCalled) {

            // this is after one or more data updates have been called
            // Data from previous calls may have been buffered
            byte[] results = null;

            // OCKDebug.Msg(debPrefix, methodName, "inputOffset=" + inputOffset + "
            // inputLen=" + inputLen + " input[]", input);
            try {
                results = doFinalForUpdates(input, inputOffset, inputLen);
                resetVars(false);

                if (generateIV) {
                    /*
                     * Generate the next internal AES-GCM initialization vector per NIST SP 800-38D
                     */
                    newIV = generateInternalIV(false).clone();
                }

                return results;
            } catch (IllegalStateException e) {
                resetVars(true);

                throw e;
            } catch (OCKException e) {
                // OCKDebug.Msg(debPrefix, methodName, "OCKException encountered = " +
                // e.getMessage());

                if (!encrypting) {
                    AEADBadTagException abte = new AEADBadTagException(
                            "Unable to perform engine doFinal; "
                                    + "Possibly a bad tag or bad padding or illegalBlockSize");
                    provider.setOCKExceptionCause(abte, e);
                    resetVars(true);
                    throw abte;
                } else {
                    resetVars(true);
                    throw provider
                            .providerException("unable to perform to engineDoFinal encrypting ", e);
                }
            }

        }

        try {
            byte[] output;

            if (encrypting) {
                output = new byte[inputLen + tagLenInBytes];
            } else {
                if (inputLen < tagLenInBytes) {
                    resetVars(true);
                    throw new AEADBadTagException("Input too short - not enough bytes for the tag");
                } else {
                    output = new byte[inputLen - tagLenInBytes];
                }
            }

            int outputLen = engineDoFinal(input, inputOffset, inputLen, output, 0);
            resetVars(false);
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
            resetVars(true);
            // OCKDebug.Msg(debPrefix, methodName, "OCKException seen");
            if (!encrypting) {

                AEADBadTagException abte = new AEADBadTagException(
                        "Unable to perform engine doFinal; "
                                + "Possibly a bad tag or bad padding or illegalBlockSize");

                provider.setOCKExceptionCause(abte, e);
                throw abte;
            } else {
                throw provider.providerException("unable to perform to engineDoFinal ", e);
            }
        } catch (IllegalStateException ex) {
            resetVars(true);
            throw ex;
        }

    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        //final String methodName = "engineDoFinal";
        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();

        if (updateCalled) {
            // this is after one or more data updates have been called
            try {
                int ret = 0;
                ret = doFinalForUpdates(input, inputOffset, inputLen, output, outputOffset);
                // OCKDebug.Msg (debPrefix, methodName, "Ret from engineDoFinal: " + ret);
                // OCKDebug.Msg (debPrefix, methodName, "Ret from engineDoFinal: ");
                resetVars(false);

                if (generateIV) {
                    /*
                     * Generate the next internal AES-GCM initialization vector per NIST SP 800-38D
                     */
                    newIV = generateInternalIV(false).clone();
                }

                return ret;
            } catch (IllegalStateException e) {
                // OCKDebug.Msg (debPrefix, methodName, "Ret from engineDoFinal: ");
                resetVars(true);
                //                    updateCalled = false;
                //                    requireReinit = true;

                throw e;
            } catch (OCKException e) {

                //updateCalled = false;
                //
                //requireReinit = true;

                if (!encrypting) {
                    AEADBadTagException abte = new AEADBadTagException(e.getMessage());
                    provider.setOCKExceptionCause(abte, e);
                    // OCKDebug.Msg (debPrefix, methodName, "Ret from engineDoFinal: ");
                    resetVars(true);
                    throw abte;
                } else {
                    resetVars(true);
                    throw new ProviderException(
                            "engineDoFinal cannot perform update during encryption");
                }

            }
        }

        try {
            if (encrypting) {
                if ((output == null) || (output.length - outputOffset < inputLen + tagLenInBytes)) {
                    throw new ShortBufferException(
                            "Output buffer is not long enough to contain ciphertext and tag");
                }

                /*
                 * switch to the newly generated IV only at this point, need to keep the old IV
                 * around since getIV() might be called up to this point
                 */

                if (generateIV && newIV != null) {
                    IV = newIV.clone();
                    newIV = null;
                }
                if ((!sbeInLastFinalEncrypt) && encrypting && !initCalledInEncSeq) {
                    boolean sameKeyIv = checkKeyAndNonce(Key.getValue(), IV, lastEncKey, lastEncIv);
                    if (sameKeyIv) {
                        resetVars(true);
                        throw new IllegalStateException("Cannot reuse iv for AESGCM encryption");
                    }
                }

                int ret = GCMCipher.doGCMFinal_Encrypt(ockContext, Key.getValue(), IV, tagLenInBytes, input,
                        inputOffset, inputLen, output, outputOffset, authData, provider);
                authData = null; // Before returning from doFinal(), restore AAD to uninitialized state

                if (generateIV) {
                    /*
                     * Generate the next internal AES-GCM initialization vector per NIST SP 800-38D
                     */
                    newIV = generateInternalIV(false).clone();
                }

                return ret;
            } else {
                // decrypting
                if (inputLen < tagLenInBytes) {
                    throw new AEADBadTagException("Input too short - need tag");
                }

                if ((output == null)
                        || ((output.length - outputOffset) < (inputLen - tagLenInBytes))) {
                    throw new ShortBufferException("Output buffer too small");
                }

                int ret = GCMCipher.doGCMFinal_Decrypt(ockContext, Key.getValue(), IV, tagLenInBytes, input,
                        inputOffset, inputLen, output, outputOffset, authData, provider);
                authData = null; // Before returning from doFinal(), restore AAD to uninitialized state
                return ret;
            }
        } catch (AEADBadTagException e) {
            resetVars(true);
            AEADBadTagException abte = new AEADBadTagException(e.getMessage());
            provider.setOCKExceptionCause(abte, e);
            throw abte;
        } catch (BadPaddingException ock_bpe) {
            resetVars(true);
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            resetVars(true);
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            sbeInLastFinalEncrypt = encrypting;
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (com.ibm.crypto.plus.provider.ock.OCKException ock_excp) {
            resetVars(true);
            AEADBadTagException tagexcp = new AEADBadTagException(ock_excp.getMessage());
            provider.setOCKExceptionCause(tagexcp, ock_excp);
            throw tagexcp;
        } catch (Exception e) {
            resetVars(true);
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    private byte[] doFinalForUpdates(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException, AEADBadTagException,
            IllegalStateException, OCKException {
        //final String methodName = "byte[] doFinalForUpdates";
        // OCKDebug.Msg(debPrefix, methodName, "inputOffset=" + inputOffset + "
        // inputLen=" + inputLen + " input[]", input);
        checkReinit();
        try {
            byte[] output = new byte[engineGetOutputSize(inputLen)];
            // OCKDebug.Msg(debPrefix, methodName, "output length=" + output.length +
            // "inputOffset=" + inputOffset + " ", input);
            byte[] finalBuf = prepareInputBuffer(input, inputOffset, inputLen, output, 0);
            // OCKDebug.Msg(debPrefix, methodName, "finalBuf.length=" + finalBuf.length + "
            // ", finalBuf);
            int finalOffset = (finalBuf == input) ? inputOffset : 0;
            int finalBufLen = (finalBuf == input) ? inputLen : finalBuf.length;

            // OCKDebug.Msg(debPrefix, methodName, "finalOffset=" + finalOffset +
            // "finalBufLen=" + finalBufLen);
            int outLen = fillOutputBuffer(finalBuf, finalOffset, output, 0, finalBufLen, input);
            // OCKDebug.Msg(debPrefix, methodName, "fillOutputBuffer returned " + "outLen="
            // + outLen);

            endDoFinal();

            if (outLen < output.length) {
                byte[] copy = Arrays.copyOf(output, outLen);
                if (!encrypting) {
                    // Zero out internal (ouput) array
                    Arrays.fill(output, (byte) 0x00);
                }
                return copy;
            } else {
                return output;
            }
        } catch (ShortBufferException e) {
            // never thrown
            throw new ProviderException("Unexpected exception", e);
        }
    }



    private int doFinalForUpdates(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException, AEADBadTagException, IllegalStateException, OCKException {
        //final String methodName = "doFinalForUpdates";
        checkReinit();

        int estOutSize = engineGetOutputSize(inputLen);
        int outputCapacity = checkOutputCapacity(output, outputOffset, estOutSize);
        int offset = (!encrypting) ? 0 : outputOffset; // 0 for decrypting
        byte[] finalBuf = prepareInputBuffer(input, inputOffset, inputLen, output, outputOffset);
        byte[] outWithPadding = null; // for decrypting only

        int finalOffset = (finalBuf == input) ? inputOffset : 0;
        int finalBufLen = (finalBuf == input) ? inputLen : finalBuf.length;

        if (!encrypting) {
            // create temporary output buffer so that only "real"
            // data bytes are passed to user's output buffer.
            outWithPadding = new byte[estOutSize];
        }

        byte[] outBuffer = !encrypting ? outWithPadding : output;

        int outLen = fillOutputBuffer(finalBuf, finalOffset, outBuffer, offset, finalBufLen, input);
        // OCKDebug.Msg(debPrefix, methodName, "outLen from fillOutputBuffer =" +
        // outLen);

        if (!encrypting) {
            if (outputCapacity < outLen) {
                throw new ShortBufferException("Output buffer too short: " + (outputCapacity)
                        + " bytes given, " + outLen + " bytes needed");
            }
            // copy the result into user-supplied output buffer
            System.arraycopy(outWithPadding, 0, output, outputOffset, outLen);
            // decrypt mode. Zero out output data that's not required
            Arrays.fill(outWithPadding, (byte) 0x00);
        }
        endDoFinal();
        // OCKDebug.Msg(debPrefix, methodName, "outLen=" + outLen);
        return outLen;
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

        int totalLen = Math.addExact(buffered, inputLen);

        try {
            return GCMCipher.getOutputSize(totalLen, encrypting, tagLenInBytes);
        } catch (Exception e) {
            throw provider.providerException("Unable to get output size", e);
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (IV == null)
            return null;
        GCMParameterSpec gcmps = new GCMParameterSpec(tagLenInBytes * 8, engineGetIV());
        AlgorithmParameters gcmParams;
        try {
            gcmParams = AlgorithmParameters.getInstance("GCM");
            gcmParams.init(gcmps);
        } catch (NoSuchAlgorithmException nsae) {
            // should never happen
            throw new ProviderException(nsae.getMessage());
        } catch (InvalidParameterSpecException ipse) {
            // should never happen
            throw new ProviderException(ipse.getMessage());
        }
        return gcmParams;
    }

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
            generateIV = true;
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }

        /*
         * Generate the first internal AES-GCM initialization vector per NIST SP 800-38D
         */
        byte[] tempIV = generateInternalIV(true);

        if (encrypting) {
            byte[] keyBytes = key.getEncoded().clone();
            requireReinit = Arrays.equals(tempIV, lastEncIv)
                    && MessageDigest.isEqual(keyBytes, lastEncKey);
            if (requireReinit) {
                throw new ProviderException("Cannot reuse iv for GCM encryption");
            }
            lastEncIv = tempIV;
            lastEncKey = keyBytes;
        } else {
            requireReinit = false;
        }

        internalInit(opmode, key, tempIV);
        requireReinit = false;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            encrypting = false;
        } else {
            encrypting = true;
            generateIV = false;
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }
        if (params != null) { // if we have a ParameterSpec, check to see if it
                              // is GCMParameterSpec
            if (params instanceof GCMParameterSpec) {
                byte[] ivTemp = ((GCMParameterSpec) params).getIV();
                if (ivTemp.length == 0) {
                    if (encrypting) {
                        tagLenInBytes = ((GCMParameterSpec) params).getTLen() / 8;

                        byte[] newIV = generateInternalIV(true);
                        byte[] keyBytes = key.getEncoded().clone();

                        requireReinit = Arrays.equals(newIV, lastEncIv)
                                && MessageDigest.isEqual(keyBytes, lastEncKey);
                        if (requireReinit) {
                            throw new InvalidAlgorithmParameterException(
                                    "Cannot reuse iv for GCM encryption");
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
                    tagLenInBytes = ((GCMParameterSpec) params).getTLen() / 8;

                    if (encrypting) {
                        byte[] keyBytes = key.getEncoded().clone();
                        requireReinit = Arrays.equals(ivTemp, lastEncIv)
                                && MessageDigest.isEqual(keyBytes, lastEncKey);
                        if (requireReinit) {
                            throw new InvalidAlgorithmParameterException(
                                    "Cannot reuse iv for GCM encryption");
                        }
                        lastEncIv = ivTemp.clone();
                        lastEncKey = keyBytes;
                        // ibuffer = null;
                    } else {
                        requireReinit = false;
                        // ibuffer = new ByteArrayOutputStream();
                        // minBytes = tagLenInBytes;
                    }

                    internalInit(opmode, key, ((GCMParameterSpec) params).getIV().clone());
                }
            } else {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter " + "type: GCM " + "expected");
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

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {

        if ((opmode == Cipher.DECRYPT_MODE) || (opmode == Cipher.UNWRAP_MODE)) {
            encrypting = false;
        } else {
            encrypting = true;
            generateIV = false;
        }

        if (key == null) {
            throw new InvalidKeyException("No key given");
        }

        if (params != null) {
            GCMParameterSpec ivSpec = null;
            try {
                ivSpec = params.getParameterSpec(GCMParameterSpec.class);
            } catch (InvalidParameterSpecException ipse) {
                throw new InvalidAlgorithmParameterException(
                        "Wrong parameter " + "type: GCM " + "expected");
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
        initCalledInEncSeq = false;
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
            this.Key.setValue(rawKey.clone());
            this.IV = iv.clone();
            this.encrypting = isEncrypt;
            this.initialized = true;
            this.initCalledInEncSeq = true;
            this.authData = null; // Before returning from internalInit(), restore AAD to uninitialized state
            this.updateCalled = false;
            this.sbeInLastFinalEncrypt = false;
            this.sbeInLastUpdateEncrypt = false;
            this.buffered = 0;
            Arrays.fill(buffer, (byte) 0x0);

        } catch (Exception e) {
            resetVars(false);
            throw provider.providerException("Failed to init cipher", e);
        }
    }

    /*
     * Generate internal AES-GCM initialization vector per NIST SP 800-38D
     * sections: 5.2.1.1 Input Data 8.2.1 Deterministic Construction 8.3
     * Constraints on Number of Invocations
     */

    private byte[] generateInternalIV(boolean firstIV) throws IllegalStateException {

        byte[] generatedIV = null;

        /*
         * The fixed device and invocation counter fields are initialized once per
         * cipher instance.
         */

        if (firstIV) {
            if (cryptoRandom == null) {
                cryptoRandom = provider.getSecureRandom(null);
            }
            generatedIVDevField = new byte[GENERATED_IV_DEVICE_FIELD_LENGTH];
            cryptoRandom.nextBytes(generatedIVDevField);
            generatedIVCtrField = new BigInteger(GENERATED_IV_MAX_INVOCATIONS);
        }

        /*
         * The invocation counter is initialized to the maximum allowable invocations
         * for the current crypto key. With each invocation it is decremented to
         * indicate the remaining number of invocations. A zero counter indicates that
         * the cipher must be reinitialized with a fresh crypto key before continuing.
         */

        if (!generatedIVCtrField.equals(BigInteger.ZERO)) {

            /* Combine the IV fixed device field and invocation counter field */

            generatedIV = new byte[GENERATED_IV_TOTAL_LENGTH];

            System.arraycopy(generatedIVDevField, 0, generatedIV, 0,
                    GENERATED_IV_DEVICE_FIELD_LENGTH);

            /*
             * Since BigInteger uses the minimum number of bytes to represent integer
             * values, the length of the generated IV invocation field is not fixed, and
             * will shrink as it is decremented. So, we have to allow for that in the offset
             * calculation.
             */

            byte[] genIVCtrFieldByteArray = stripOffSignByte(generatedIVCtrField.toByteArray());
            int genIVCtrFieldByteArrayLength = genIVCtrFieldByteArray.length;
            int genIVCtrFieldByteArrayOffset = GENERATED_IV_TOTAL_LENGTH
                    - genIVCtrFieldByteArrayLength;

            System.arraycopy(genIVCtrFieldByteArray, 0, generatedIV, genIVCtrFieldByteArrayOffset,
                    genIVCtrFieldByteArrayLength);

            /* Decrement the remaining generated IV invocations counter field */

            generatedIVCtrField = generatedIVCtrField.subtract(BigInteger.ONE);

        } else {

            /*
             * The maximum number of invocations have been exhausted. So, the crypto key is
             * stale and the user must reinitialize the cipher instance with a fresh crypto
             * key before continuing with the encryption process to be NIST SP 800-38D
             * compliant.
             */

            throw new IllegalStateException(
                    "The maximum number of IV invocations for the current key "
                            + "have been exhausted.");
        }

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

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        //final String methodName = "byte[] engineUpdate";

        if (!GCMCipher.gcmUpdateSupported()) {
            throw new ProviderException(
                    "engineUpdate is not supported for AESGCM on this platform; only engineDoFinal is supported");
        }

        boolean firstUpdate = !updateCalled;
        // OCKDebug.Msg(debPrefix, methodName, "3 paraemters firstUpdate = " +
        // firstUpdate + "encrypting = " + encrypting + "input.length=" + input.length +
        // " inputOffset=" + inputOffset + " inputLen=" + inputLen);
        byte[] updateBytes = null;
        try {
            updateBytes = doUpdate(input, inputOffset, inputLen, firstUpdate);
        } catch (IllegalBlockSizeException | BadPaddingException e) {

            throw this.provider.providerException("Unable to perform update", e);
        }
        updateCalled = true;
        return updateBytes;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        //final String methodName = "int engineUpdate";
        if (!GCMCipher.gcmUpdateSupported()) {
            throw new ProviderException(
                    "engineUpdate is not supported for AESGCM on this platform; only engineDoFinal is supported");
        }
        boolean firstUpdate = !updateCalled;

        // OCKDebug.Msg(debPrefix, methodName, "engineUpdate 5 parameters firstUpdate =
        // " + firstUpdate);
        // OCKDebug.Msg(debPrefix, methodName, "5 paraemters firstUpdate = " +
        // firstUpdate + "encrypting = " + encrypting + "input.length=" + input.length +
        // " inputOffset=" + inputOffset + " inputLen=" + inputLen);
        int retcode = 0;
        try {
            retcode = doUpdate(input, inputOffset, inputLen, output, outputOffset, firstUpdate);
        } catch (IllegalBlockSizeException e) {

            throw this.provider
                    .providerException("Unable to perform update IllegalBlockSize exception", e);
        } catch (BadPaddingException e) {

            throw this.provider.providerException("Unable to perform update BadPadding exception",
                    e);
        }
        updateCalled = true;
        return retcode;
    }

    protected byte[] doUpdate(byte[] input, int inputOffset, int inputLen, boolean firstUpdate)
            throws IllegalBlockSizeException, BadPaddingException, AEADBadTagException {

        //final String methodName = "byte[] doUpdate";
        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        checkReinit();

        // OCKDebug.Msg(debPrefix, methodName, "DoUpdate returning byte[] encrypting
        // flag=" + String.valueOf(encrypting) + " inputLen=" + inputLen +
        // "inputOffset=" + inputOffset + " input.length=" + input.length);

        try {
            //Needs to account for buffered. JIRA-48,  IJ47669
            byte[] output = new byte[inputLen + buffered];

            // OCKDebug.Msg(debPrefix, methodName, "calling doUpdate after allocating output
            // buffer");
            int outputLen = doUpdate(input, inputOffset, inputLen, output, 0, firstUpdate);
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
            resetVars(true);
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }


    protected int doUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, boolean firstUpdate)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        //final String methodName = "int doUpdate";
        // OCKDebug.Msg(debPrefix, methodName, " 5 paramters firstUpdate=" + firstUpdate
        // + " encrypting=" + String.valueOf(encrypting) + " inputOffset=" + inputOffset
        // + " inputLen=" + inputLen + " outputOffset=" + outputOffset + "
        // output.length=" + output.length);
        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }

        checkReinit();

        // OCKDebug.Msg(debPrefix, methodName, " 5 paramters firstUpdate=" + firstUpdate
        // + " encrypting=" + String.valueOf(encrypting) + " inputOffset=" + inputOffset
        // + " inputLen=" + inputLen + " outputOffset=" + outputOffset + "
        // output.length=" + output.length);
        // OCKDebug.Msg(debPrefix, methodName, "buffered = " + buffered + " inoutLen=" +
        // inputLen + " minBytes = " + minBytes + " block size = " + blockSize +
        // "unitBytes=" + unitBytes);
        int len = Math.addExact(buffered, inputLen);

        if (!encrypting) {
            len -= blockSize;
        }
        // OCKDebug.Msg(debPrefix, methodName, "len = " + len + "len%unitBytes=" + (len
        // % unitBytes));
        len = (len > 0 ? (len - (len % unitBytes)) : 0);
        // OCKDebug.Msg(debPrefix, methodName, "len = " + len);

        if ((output == null) || ((output.length - outputOffset) < len)) {
            // OCKDebug.Msg(debPrefix, methodName, "throwing Short buffer exception");
            sbeInLastUpdateEncrypt = encrypting;
            throw new ShortBufferException(
                    "Output buffer must be (at least) " + len + " bytes long");
        }
        int outLen = 0;

        // Check for IV and Key.

        // OCKDebug.Msg(debPrefix, methodName, "is length greater than 0 " + len);
        try {
            // first do Init And AAED
            if (firstUpdate) {
                if (!encrypting) {
                    // OCKDebug.Msg(debPrefix, methodName, "Calling do_GCM_InitForUpdateDecrypt");
                    outLen = GCMCipher.do_GCM_InitForUpdateDecrypt(ockContext, Key.getValue(), IV,
                            tagLenInBytes, buffer, 0, len, output, outputOffset, authData, provider);
                    // OCKDebug.Msg(debPrefix, methodName, "returning ret from
                    // InitForUpdateDecrypt=" + outLen);
                } else {
                    if (!initCalledInEncSeq && !sbeInLastUpdateEncrypt) {
                        if (generateIV && (newIV != null)) {
                            IV = newIV.clone();
                            newIV = null;
                        }
                        boolean sameKeyIv = checkKeyAndNonce(Key.getValue(), IV, lastEncKey, lastEncIv);
                        if (sameKeyIv) {
                            resetVars(true);
                            throw new IllegalStateException(
                                    "Cannot reuse iv for AESGCM encryption");
                        }
                    }
                    // OCKDebug.Msg(debPrefix, methodName, "Calling do_GCM_InitForUpdateEncrypt");
                    outLen = GCMCipher.do_GCM_InitForUpdateEncrypt(ockContext, Key.getValue(), IV,
                            tagLenInBytes, buffer, 0, len, output, outputOffset, authData, provider);
                    // OCKDebug.Msg(debPrefix, methodName, "returning ret from
                    // InitForUpdateEncrypt=" + outLen);
                }
            }
            // if (len != 0) { // there is some work to do
            if (len > 0) {
                // OCKDebug.Msg(debPrefix, methodName, "There is some work to do" + len);
                if ((input == output) && (outputOffset - inputOffset < inputLen)
                        && (inputOffset - outputOffset < buffer.length)) {
                    // OCKDebug.Msg(debPrefix, methodName, "Overlapping input and output ");
                    // copy 'input' out to avoid its content being
                    // overwritten prematurely.

                    input = Arrays.copyOfRange(input, inputOffset,
                            Math.addExact(inputOffset, inputLen));
                    inputOffset = 0;
                }

                // OCKDebug.Msg(debPrefix, methodName, "buffered during decrypt=" + buffered );
                if (len <= buffered) {
                    // all to-be-processed data are from 'buffer'
                    // OCKDebug.Msg(debPrefix, methodName, "all to-be-processed data are from
                    // 'buffer'");

                    if (!encrypting) {

                        /*
                         * switch to the newly generated IV only at this point, need to keep the old IV
                         * around since getIV() might be called up to this point
                         */
                        // OCKDebug.Msg(debPrefix, methodName, "Decrypting");
                        // OCKDebug.Msg(debPrefix, methodName, "Checks all passed Calling
                        // GCMCipher.do_GCM_UpdateDecrypt");

                        outLen = GCMCipher.do_GCM_UpdForUpdateDecrypt(ockContext, Key.getValue(), IV,
                                tagLenInBytes, buffer, 0, len, output, outputOffset, authData, provider);

                        // OCKDebug.Msg(debPrefix, methodName, "returning ret from
                        // GCMCipher.do_GCM_UpdForUpdateDecrypt=" + outLen);

                        // outLen = cipher.decrypt(buffer, 0, len, output, outputOffset);
                    } else { // decrypting
                        // OCKDebug.Msg(debPrefix, methodName, "Encrypting");
                        // OCKDebug.Msg(debPrefix, methodName, "FirstUpdate generateIV");

                        outLen = GCMCipher.do_GCM_UpdForUpdateEncrypt(ockContext, Key.getValue(), IV,
                                tagLenInBytes, buffer, 0, len, output, outputOffset, authData, provider);
                        // OCKDebug.Msg(debPrefix, methodName, "returning ret from
                        // GCMCipher.do_GCM_UpdForUpdateEncrypt=" + outLen);
                        // outLen = cipher.encrypt(buffer, 0, len, output, outputOffset);
                    } // decrypting
                    buffered -= len;
                    if (buffered != 0) {
                        System.arraycopy(buffer, len, buffer, 0, buffered);
                    }
                } else { // len > buffered

                    // OCKDebug.Msg(debPrefix, methodName, "len > buffered branch");
                    int inputConsumed = len - buffered;
                    // OCKDebug.Msg(debPrefix, methodName, "inputConsumed=" + inputConsumed);
                    int temp;
                    if (buffered > 0) {
                        int bufferCapacity = buffer.length - buffered;
                        if (bufferCapacity != 0) {
                            // OCKDebug.Msg(debPrefix, methodName, "buffered capacity != 0");
                            temp = Math.min(bufferCapacity, inputConsumed);
                            if (unitBytes != blockSize) {
                                temp -= (Math.addExact(buffered, temp) % unitBytes);
                            }
                            System.arraycopy(input, inputOffset, buffer, buffered, temp);
                            inputOffset = Math.addExact(inputOffset, temp);
                            inputConsumed -= temp;
                            inputLen -= temp;
                            buffered = Math.addExact(buffered, temp);
                        }
                        // process 'buffer'. When finished we can null out 'buffer'
                        // Only necessary to null out if buffer holds data for encryption
                        if (!encrypting) {
                            outLen = GCMCipher.do_GCM_UpdForUpdateDecrypt(ockContext, Key.getValue(), IV,
                                    tagLenInBytes, buffer, 0, buffered, output, outputOffset,
                                    authData, provider);
                            // outLen = cipher.decrypt(buffer, 0, buffered, output, outputOffset);
                        } else { // decrypting
                            outLen = GCMCipher.do_GCM_UpdForUpdateEncrypt(ockContext, Key.getValue(), IV,
                                    tagLenInBytes, buffer, 0, buffered, output, outputOffset,
                                    authData, provider);
                            // outLen = cipher.encrypt(buffer, 0, buffered, output, outputOffset);
                            // encrypt mode. Zero out internal (input) buffer
                            Arrays.fill(buffer, (byte) 0x00);
                        } // encrypting
                        outputOffset = Math.addExact(outputOffset, outLen);
                        buffered = 0;
                    }
                    if (inputConsumed > 0) { // still has input to process

                        // OCKDebug.Msg(debPrefix, methodName, "still has input to process");
                        if (!encrypting) {

                            outLen += GCMCipher.do_GCM_UpdForUpdateDecrypt(ockContext, Key.getValue(), IV,
                                    tagLenInBytes, input, inputOffset, inputConsumed, output,
                                    outputOffset, authData, provider);
                            // outLen += cipher.decrypt(input, inputOffset, inputConsumed,
                            // output, outputOffset);
                        } else {

                            outLen += GCMCipher.do_GCM_UpdForUpdateEncrypt(ockContext, Key.getValue(), IV,
                                    tagLenInBytes, input, inputOffset, inputConsumed, output,
                                    outputOffset, authData, provider);

                        }
                        inputOffset += inputConsumed;
                        inputLen -= inputConsumed;
                    } // inputconsumed > 0

                }
            }

        } catch (IllegalStateException ock_illse) {
            sbeInLastUpdateEncrypt = false;
            IllegalStateException illse = new IllegalStateException(ock_illse.getMessage());
            provider.setOCKExceptionCause(illse, ock_illse);
            throw illse;
        } catch (AEADBadTagException e) {
            sbeInLastUpdateEncrypt = false;
            AEADBadTagException abte = new AEADBadTagException(e.getMessage());
            provider.setOCKExceptionCause(abte, e);
            throw abte;
        } catch (BadPaddingException ock_bpe) {
            sbeInLastUpdateEncrypt = false;
            BadPaddingException bpe = new BadPaddingException(ock_bpe.getMessage());
            provider.setOCKExceptionCause(bpe, ock_bpe);
            throw bpe;
        } catch (IllegalBlockSizeException ock_ibse) {
            sbeInLastUpdateEncrypt = false;
            IllegalBlockSizeException ibse = new IllegalBlockSizeException(ock_ibse.getMessage());
            provider.setOCKExceptionCause(ibse, ock_ibse);
            throw ibse;
        } catch (ShortBufferException ock_sbe) {
            sbeInLastUpdateEncrypt = encrypting;
            ShortBufferException sbe = new ShortBufferException(ock_sbe.getMessage());
            provider.setOCKExceptionCause(sbe, ock_sbe);
            throw sbe;
        } catch (com.ibm.crypto.plus.provider.ock.OCKException ock_excp) {
            sbeInLastUpdateEncrypt = false;
            AEADBadTagException tagexcp = new AEADBadTagException(ock_excp.getMessage());
            provider.setOCKExceptionCause(tagexcp, ock_excp);
            throw tagexcp;
        } catch (Exception e) {
            sbeInLastUpdateEncrypt = false;
            throw provider.providerException("Failure in engineUpdate", e);
        }

        // Store remaining input into 'buffer' again
        if (inputLen > 0) {
            // V OCKDebug.Msg(methodName, debPrefix,
            // "Store remaining input into 'buffer' again");
            System.arraycopy(input, inputOffset, buffer, buffered, inputLen);
            buffered = Math.addExact(buffered, inputLen);
        }
        sbeInLastUpdateEncrypt = false;
        return outLen;
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

        this.authData = new byte[len];
        System.arraycopy(src, offset, authData, 0, len);
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        //final String methodName = "engineUpdateAAD";

        if (!initialized) {
            throw new IllegalStateException("Cipher has not been initialized");
        }
        // OCKDebug.Msg(debPrefix, methodName, "engingeUpdateAAD called with ByteBuffer"
        // + src);
        checkReinit();
        if (updateCalled) {
            throw new IllegalStateException(
                    "AAD must be supplied before encryption/decryption starts");
        }
        this.authData = new byte[src.remaining()];
        src.get(authData, 0, authData.length);
    }

    private int fillOutputBuffer(byte[] finalBuf, int finalOffset, byte[] output, int outOfs,
            int finalBufLen, byte[] input) throws ShortBufferException, BadPaddingException,
            IllegalBlockSizeException, OCKException {
        //final String methodName = "fillOutputBuffer";
        // OCKDebug.Msg(debPrefix, methodName, "Entering finalOffset = ", finalBuf);
        int len;
        try {
            len = finalNoPadding(finalBuf, finalOffset, output, outOfs, finalBufLen);
            // OCKDebug.Msg(debPrefix, methodName, "finalNoPadding returned len = ", len);
            return len;
        } finally {
            if (encrypting) {
                // reset after doFinal() for GCM encryption
                //requireReinit = true;
                if (finalBuf != input) {
                    // done with internal finalBuf array. Copied to output
                    Arrays.fill(finalBuf, (byte) 0x00);
                }
            }
        }
    }

    private int finalNoPadding(byte[] in, int inOfs, byte[] out, int outOfs, int len)
            throws IllegalBlockSizeException, AEADBadTagException, BadPaddingException,
            ShortBufferException, OCKException {

        //final String methodName = "finalNoPadding";
        // OCKDebug.Msg(debPrefix, methodName, "Entering in" + in + " len=" + 0);

        int outLen = 0;

        if (!encrypting) {
            outLen = GCMCipher.do_GCM_FinalForUpdateDecrypt(ockContext, Key.getValue(), IV, tagLenInBytes, in,
                    inOfs, len, out, outOfs, authData, provider);
            // OCKDebug.Msg(debPrefix, methodName, "outLen from
            // GCMCipher.do_GCM_FinalForUpdateDecrypt=" + outLen);

        } else {
            outLen = GCMCipher.do_GCM_FinalForUpdateEncrypt(ockContext, Key.getValue(), IV, tagLenInBytes, in,
                    inOfs, len, out, outOfs, authData, provider);
            // OCKDebug.Msg(debPrefix, methodName, "outLen from
            // GCMCipher.do_GCM_FinalForUpdateEncrypt=" + outLen);

        }

        return outLen;
    }

    private int checkOutputCapacity(byte[] output, int outputOffset, int estOutSize)
            throws ShortBufferException {
        //final String methodName = "checkOutputCapacity";
        // OCKDebug.Msg(debPrefix, methodName, "Entering outputOffset=" + outputOffset +
        // " estOutSize=" + estOutSize, output);
        // check output buffer capacity.
        // if we are decrypting with padding applied, we can perform this
        // check only after we have determined how many padding bytes there
        // are.
        int outputCapacity = output.length - outputOffset;
        if ((output == null) || (outputCapacity < estOutSize)) {
            throw new ShortBufferException(
                    "Output buffer must be " + "(at least) " + estOutSize + " bytes long");
        }
        // OCKDebug.Msg(debPrefix, methodName, "Exiting outputCapacity=" +
        // outputCapacity);
        return outputCapacity;
    }



    /**
     * You'd better only do this if you KNOW that this is a positive number!!!
     * BigInteger.toByteArray() will output an extra leading 00 byte if the
     * high-order bit is on in the first nibble of output. This will really hose
     * up HASHes.
     *
     * @param bytes
     *            byte array with potential extra byte of zero in front
     * @return
     */

    private byte[] stripOffSignByte(byte[] bytes) {
        byte[] answer = bytes;
        if ((answer != null) && (answer.length > 1) && ((answer.length % 2) == 1)
                && (answer[0] == 0x00) && ((answer[1] & 0x80) == 0x80)) {
            byte[] newanswer = new byte[answer.length - 1];
            System.arraycopy(answer, 1, newanswer, 0, newanswer.length);

            answer = newanswer;
        }
        return answer;
    }


    private byte[] prepareInputBuffer(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws IllegalBlockSizeException, ShortBufferException {

        //final String methodName = "prepareInputBuffer";

        //OCKDebug.Msg(debPrefix, methodName,  "Entering inputOffset=" + inputOffset + "outputOffset=" + outputOffset,  input);
        // calculate total input length
        int len = Math.addExact(buffered, inputLen);
        //OCKDebug.Msg(debPrefix, methodName,"buffered=" + buffered + "inputLen=" + inputLen + "len=" +  len);

        /*
         * prepare the final input, assemble a new buffer if any
         * of the following is true:
         *  - 'input' and 'output' are the same buffer
         *  - there are internally buffered bytes
         *  - doing encryption and padding is needed
         */
        if ((buffered != 0) || (encrypting)
                || ((input == output) && (outputOffset - inputOffset < inputLen)
                        && (inputOffset - outputOffset < buffer.length))) {
            byte[] finalBuf;

            finalBuf = new byte[len];
            if (buffered != 0) {
                System.arraycopy(buffer, 0, finalBuf, 0, buffered);
                if (encrypting) {
                    // done with input buffer. We should zero out the
                    // data if we're in encrypt mode.
                    Arrays.fill(buffer, (byte) 0x00);
                }
            }
            if (inputLen != 0) {
                System.arraycopy(input, inputOffset, finalBuf, buffered, inputLen);
            }
            //OCKDebug.Msg(debPrefix, methodName,"Exiting finalBuf=", finalBuf);
            return finalBuf;
        }
        //OCKDebug.Msg(debPrefix, methodName,"Exiting input as output =", input);
        return input;
    }


    /**
     * Returns the mode of this cipher.
     *
     * @return the parsed cipher mode
     */
    int getMode() {
        return (encrypting) ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    }

    private static int getNumOfUnit(String mode, int offset, int blockSize)
            throws NoSuchAlgorithmException {
        //final String methodName = "getNumOfUnit";
        //OCKDebug.Msg("AESGCMCipher", methodName, "Enter mode=" + mode + "offset=" + offset + "blockSize=" + blockSize);

        int result = blockSize; // use blockSize as default value
        if (mode.length() > offset) {
            int numInt;
            try {
                Integer num = Integer.valueOf(mode.substring(offset));
                numInt = num.intValue();
                result = numInt >> 3;
            } catch (NumberFormatException e) {
                throw new NoSuchAlgorithmException("Algorithm mode: " + mode + " not implemented");
            }
            if ((numInt % 8 != 0) || (result > blockSize)) {
                throw new NoSuchAlgorithmException("Invalid algorithm mode: " + mode);
            }
        }
        //OCKDebug.Msg("AESGCMCipher", methodName, "Exiting result=" + result);
        return result;
    }

    private void endDoFinal() {
        buffered = 0;
        diffBlocksize = blockSize;
    }

    private void checkReinit() {
        if (requireReinit) {
            throw new IllegalStateException(
                    "Must use either different key or iv for GCM encryption");
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

    //Reset class variables after an exception
    private void resetVars(boolean afterFailure) {
        sbeInLastFinalEncrypt = false;
        if (afterFailure) {
            this.requireReinit = true;
            authData = null;
            this.aadDone = false;
        }
        initCalledInEncSeq = false;
        updateCalled = false;
        sbeInLastUpdateEncrypt = false;
        this.buffered = 0;
        Arrays.fill(buffer, (byte) 0x0);
    }

    private Runnable cleanOCKResources(PrimitiveWrapper.ByteArray Key) {
        return() -> {
            try {
                //JS00684 - Leave cleanup of internal variables to GCMCipher that caches them
                if (Key.getValue() != null) {
                    Arrays.fill(Key.getValue(), (byte) 0x00);
                }
            } catch (Exception e) {
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
