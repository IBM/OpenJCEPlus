/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

abstract class LegacyCipher extends CipherSpi {

    @Override
    protected abstract byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException;
    
    @Override
    protected abstract int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
        int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
    
    @Override
    protected abstract int engineGetBlockSize();

    @Override
    protected abstract int engineGetKeySize(Key key) throws InvalidKeyException;

    @Override
    protected abstract byte[] engineGetIV();

    @Override
    protected abstract int engineGetOutputSize(int inputLen);

    @Override
    protected abstract AlgorithmParameters engineGetParameters();

    @Override
    protected abstract void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException;

    @Override
    protected abstract void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
        SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException;

    @Override
    protected abstract void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException; 

    @Override
    protected abstract void engineSetMode(String mode) throws NoSuchAlgorithmException;

    @Override
    protected abstract void engineSetPadding(String padding) throws NoSuchPaddingException;

    @Override
    protected abstract byte[] engineUpdate(byte[] input, int inputOffset, int inputLen);

    @Override
    protected abstract int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
        int outputOffset) throws ShortBufferException;

    @Override
    protected abstract byte[] engineWrap(Key key) throws InvalidKeyException, IllegalBlockSizeException;

    @Override
    protected abstract Key engineUnwrap(byte[] wrappedKey, String algorithm, int type)
        throws InvalidKeyException, NoSuchAlgorithmException;

}
