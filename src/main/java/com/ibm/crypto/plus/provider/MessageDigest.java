/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.base.Digest;
import java.security.MessageDigestSpi;

abstract class MessageDigest extends MessageDigestSpi implements Cloneable {

    private OpenJCEPlusProvider provider = null;
    private Digest digest = null;

    MessageDigest(OpenJCEPlusProvider provider, String ockDigestAlgo) {
        try {
            this.provider = provider;
            this.digest = Digest.getInstance(provider.getOCKContext(), ockDigestAlgo, provider);
        } catch (Exception e) {
            throw provider.providerException("Failure in MessageDigest", e);
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
        if (input == null) {
            throw new IllegalArgumentException("No input buffer given");
        }
        if ((offset < 0) || (length < 0) || (offset > input.length - length)) {
            throw new ArrayIndexOutOfBoundsException("Range out of bounds for buffer of length " + input.length +" using offset: " + offset + ", input length: " + length);
        }
        try {
            this.digest.update(input, offset, length);
        } catch (Exception e) {
            throw provider.providerException("Failure in engineUpdate", e);
        }
    }

    @Override
    protected byte[] engineDigest() {
        try {
            return this.digest.digest();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineDigest", e);
        }
    }

    @Override
    protected int engineGetDigestLength() {
        try {
            return this.digest.getDigestLength();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineGetDigestLength", e);
        }
    }

    /*
     * This method helps in deriving PKCS12 key by performing update and digest in C
     * in an iteration count loop avoiding excess JNI calls. 
     */
    protected byte[] PKCS12KeyDeriveHelp(byte[] input, int offset, int length, int iterationCount) {
        try {
            return this.digest.PKCS12KeyDeriveHelp(input, offset, length, iterationCount);
        } catch (Exception e) {
            throw provider.providerException("Failure in PKCS12 key derivation native helper method", e);
        }
    }

    /**
     * Compares two digests for equality. Two digests are equal if they have
     * the same length and all bytes at corresponding positions are equal.
     *
     * @implNote
     * If the digests are the same length, all bytes are examined to
     * determine equality.
     *
     * @param digesta one of the digests to compare.
     *
     * @param digestb the other digest to compare.
     *
     * @return true if the digests are equal, false otherwise.
     */
    public static boolean isEqual(byte[] digesta, byte[] digestb) {
        if (digesta == digestb)
            return true;
        if (digesta == null || digestb == null) {
            return false;
        }
        if (digesta.length != digestb.length) {
            return false;
        }

        int result = 0;
        // time-constant comparison
        for (int i = 0; i < digesta.length; i++) {
            result |= digesta[i] ^ digestb[i];
        }
        return result == 0;
    }

    @Override
    protected void engineReset() {
        try {
            this.digest.reset();
        } catch (Exception e) {
            throw provider.providerException("Failure in engineReset", e);
        }
    }

    public static final class MD5 extends MessageDigest {
        public MD5(OpenJCEPlusProvider provider) {
            super(provider, "MD5"); // OCK digest name
        }
    }

    public static final class SHA1 extends MessageDigest {
        public SHA1(OpenJCEPlusProvider provider) {
            super(provider, "SHA1"); // OCK digest name
        }
    }

    public static final class SHA224 extends MessageDigest {
        public SHA224(OpenJCEPlusProvider provider) {
            super(provider, "SHA224"); // OCK digest name
        }
    }

    public static final class SHA256 extends MessageDigest {
        public SHA256(OpenJCEPlusProvider provider) {
            super(provider, "SHA256"); // OCK digest name
        }
    }

    public static final class SHA384 extends MessageDigest {
        public SHA384(OpenJCEPlusProvider provider) {
            super(provider, "SHA384"); // OCK digest name
        }
    }

    public static final class SHA512 extends MessageDigest {
        public SHA512(OpenJCEPlusProvider provider) {
            super(provider, "SHA512"); // OCK digest name
        }
    }

    public static final class SHA512_224 extends MessageDigest {
        public SHA512_224(OpenJCEPlusProvider provider) {
            super(provider, "SHA512-224"); // OCK digest name
        }
    }


    public static final class SHA512_256 extends MessageDigest {
        public SHA512_256(OpenJCEPlusProvider provider) {
            super(provider, "SHA512-256"); // OCK digest name
        }
    }

    public static final class SHA3_224 extends MessageDigest {
        public SHA3_224(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-224"); // OCK digest name
        }
    }

    public static final class SHA3_256 extends MessageDigest {
        public SHA3_256(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-256"); // OCK digest name
        }
    }

    public static final class SHA3_384 extends MessageDigest {
        public SHA3_384(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-384"); // OCK digest name
        }
    }

    public static final class SHA3_512 extends MessageDigest {
        public SHA3_512(OpenJCEPlusProvider provider) {
            super(provider, "SHA3-512"); // OCK digest name
        }
    }

    /*public static final class SHAKE128 extends MessageDigest {
        public SHAKE128(OpenJCEPlusProvider provider) {
            super(provider, "SHAKE128"); // OCK digest name
        }
    };
    public static final class SHAKE256 extends MessageDigest {
        public SHAKE_256(OpenJCEPlusProvider provider) {
            super(provider, "SHAKE256"); // OCK digest name
        } 
    };*/

    @Override
    synchronized public Object clone() throws CloneNotSupportedException {
        MessageDigest copy = (MessageDigest) super.clone();
        copy.digest = (Digest) copy.digest.clone();
        return copy;
    }
}
