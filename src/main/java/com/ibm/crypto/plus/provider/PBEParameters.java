/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.PBEParameterSpec;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;

abstract class PBEParameters extends AlgorithmParametersSpi {

    // the PBE algorithm
    private String pbeAlgorithmName = null;

    // the salt
    private byte[] salt = null;

    // the iteration count
    private int iCount = 0;

    // the cipher parameter
    private AlgorithmParameterSpec cipherParam = null;

    PBEParameters (String algorithm) {
        this.pbeAlgorithmName = algorithm;
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec)
        throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }

        this.salt = ((PBEParameterSpec) paramSpec).getSalt().clone();
        this.iCount = ((PBEParameterSpec) paramSpec).getIterationCount();
        this.cipherParam = ((PBEParameterSpec) paramSpec).getParameterSpec();
    }

    protected void engineInit(byte[] encoded)
        throws IOException {
        try {
            DerValue val = new DerValue(encoded);
            if (val.tag != DerValue.tag_Sequence) {
                throw new IOException("PBE parameter parsing error: not a sequence");
            }
            val.data.reset();

            this.salt = val.data.getOctetString();
            this.iCount = val.data.getInteger();

            if (val.data.available() != 0) {
                throw new IOException("PBE parameter parsing error: extra data");
            }
        } catch (NumberFormatException e) {
            throw new IOException("iteration count too big");
        }
    }

    protected void engineInit(byte[] encoded, String decodingMethod)
        throws IOException {
        engineInit(encoded);
    }

    protected <T extends AlgorithmParameterSpec>
            T engineGetParameterSpec(Class<T> paramSpec)
        throws InvalidParameterSpecException {
        if (paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
            return paramSpec.cast(
                new PBEParameterSpec(this.salt, this.iCount, this.cipherParam));
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        DerOutputStream out = new DerOutputStream();
        DerOutputStream bytes = new DerOutputStream();

        bytes.putOctetString(this.salt);
        bytes.putInteger(this.iCount);

        out.write(DerValue.tag_Sequence, bytes);
        return out.toByteArray();
    }

    protected byte[] engineGetEncoded(String encodingMethod)
        throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     *
     * The algorithm name pattern is: "PBEWith<prf>And<encryption>"
     * where <prf> is one of: MD5 or SHA1 and <encryption> is
     * one of: DES, DESede, RC2, or RC4 where for RC ciphers the suffix
     * is the keysize.
     */
    protected String engineToString() {
        return this.pbeAlgorithmName;
    }

    public static final class PBEWithMD5AndDES extends PBEParameters {
        public PBEWithMD5AndDES() throws NoSuchAlgorithmException {
            super("PBEWithMD5AndDES");
        }
    }

    public static final class PBEWithSHA1AndDESede extends PBEParameters {
        public PBEWithSHA1AndDESede() throws NoSuchAlgorithmException {
            super("PBEWithSHA1AndDESede");
        }
    }

    public static final class PBEWithSHA1AndRC2_40 extends PBEParameters {
        public PBEWithSHA1AndRC2_40() throws NoSuchAlgorithmException {
            super("PBEWithSHA1RC2_40");
        }
    }

    public static final class PBEWithSHA1AndRC2_128 extends PBEParameters {
        public PBEWithSHA1AndRC2_128() throws NoSuchAlgorithmException {
            super("PBEWithSHA1RC2_128");
        }
    }

    public static final class PBEWithSHA1AndRC4_40 extends PBEParameters {
        public PBEWithSHA1AndRC4_40() throws NoSuchAlgorithmException {
            super("PBEWithSHA1AndRC4_40");
        }
    }

    public static final class PBEWithSHA1AndRC4_128 extends PBEParameters {
        public PBEWithSHA1AndRC4_128() throws NoSuchAlgorithmException {
            super("PBEWithSHA1AndRC4_128");
        }
    }
}
