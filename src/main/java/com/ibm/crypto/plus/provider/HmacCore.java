/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.HMAC;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.MacSpi;
import javax.crypto.SecretKey;

abstract class HmacCore extends MacSpi {

    private OpenJCEPlusProvider provider = null;
    private HMAC hmac = null;

    HmacCore(OpenJCEPlusProvider provider, String ockDigestAlgo, int blockLength) {
        try {
            this.provider = provider;
            this.hmac = HMAC.getInstance(provider.getOCKContext(), ockDigestAlgo);
        } catch (Exception e) {
            throw provider.providerException("Failure in HmacCore", e);
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        try {
            return hmac.doFinal();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected int engineGetMacLength() {
        try {
            return hmac.getMacLength();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("HMAC does not use parameters");
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Secret key expected");
        }

        byte[] secret = key.getEncoded();
        if (secret == null) {
            throw new InvalidKeyException("Missing key data");
        }

        try {
            hmac.initialize(secret);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineInit", e);
        } finally {
            Arrays.fill(secret, (byte) 0x00);
        }
    }

    @Override
    protected void engineReset() {
        try {
            hmac.reset();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDoFinal", e);
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        byte[] singleByte = new byte[1];
        singleByte[0] = input;
        engineUpdate(singleByte, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        try {
            this.hmac.update(input, offset, length);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    // nested static class for the HmacMD5 implementation
    public static final class HmacMD5 extends HmacCore {
        public HmacMD5(OpenJCEPlusProvider provider) {
            super(provider, "MD5", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA1 implementation
    public static final class HmacSHA1 extends HmacCore {
        public HmacSHA1(OpenJCEPlusProvider provider) {
            super(provider, "SHA1", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA224 implementation
    public static final class HmacSHA224 extends HmacCore {
        public HmacSHA224(OpenJCEPlusProvider provider) {
            super(provider, "SHA224", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA256 implementation
    public static final class HmacSHA256 extends HmacCore {
        public HmacSHA256(OpenJCEPlusProvider provider) {
            super(provider, "SHA256", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA384 implementation
    public static final class HmacSHA384 extends HmacCore {
        public HmacSHA384(OpenJCEPlusProvider provider) {
            super(provider, "SHA384", 128); // OCK digest name
        }
    }

    // nested static class for the HmacSHA512 implementation
    public static final class HmacSHA512 extends HmacCore {
        public HmacSHA512(OpenJCEPlusProvider provider) {
            super(provider, "SHA512", 128); // OCK digest name
        }
    }

    // nested static class for the HmacSHA3_224 implementation
    public static final class HmacSHA3_224 extends HmacCore {
        public HmacSHA3_224(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA3_256 implementation
    public static final class HmacSHA3_256 extends HmacCore {
        public HmacSHA3_256(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256", 64); // OCK digest name
        }
    }

    // nested static class for the HmacSHA3_384 implementation
    public static final class HmacSHA3_384 extends HmacCore {
        public HmacSHA3_384(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384", 128); // OCK digest name
        }
    }

    // nested static class for the HmacSHA512 implementation
    public static final class HmacSHA3_512 extends HmacCore {
        public HmacSHA3_512(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512", 128); // OCK digest name
        }
    }
}
