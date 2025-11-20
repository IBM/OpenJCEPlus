/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;

abstract class PBEKeyFactory extends SecretKeyFactorySpi {

    private final String type;
    private OpenJCEPlusProvider provider = null;

    private PBEKeyFactory(String keytype, OpenJCEPlusProvider provider) {
        type = keytype;
        this.provider = provider;
    }

    public static final class PBEWithHmacSHA1AndAES_128 extends PBEKeyFactory {
        public PBEWithHmacSHA1AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA1AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA224AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA224AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA224AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA256AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA256AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA256AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA384AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA384AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA384AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA512AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA512AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA512_224AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA512_224AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512/224AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA512_256AndAES_128
            extends PBEKeyFactory {
        public PBEWithHmacSHA512_256AndAES_128(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512/256AndAES_128", provider);
        }
    }

    public static final class PBEWithHmacSHA1AndAES_256 extends PBEKeyFactory {
        public PBEWithHmacSHA1AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA1AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA224AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA224AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA224AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA256AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA256AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA256AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA384AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA384AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA384AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA512AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA512AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA512_224AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA512_224AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512/224AndAES_256", provider);
        }
    }

    public static final class PBEWithHmacSHA512_256AndAES_256
            extends PBEKeyFactory {
        public PBEWithHmacSHA512_256AndAES_256(OpenJCEPlusProvider provider) {
            super("PBEWithHmacSHA512/256AndAES_256", provider);
        }
    }

    /**
     * Generates a <code>SecretKey</code> object from the provided key
     * specification (key material).
     *
     * @param keySpec the specification (key material) of the secret key
     *
     * @return the secret key
     *
     * @exception InvalidKeySpecException if the given key specification
     * is inappropriate for this key factory to produce a public key.
     */
    protected SecretKey engineGenerateSecret(KeySpec keySpec)
        throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("Invalid key spec");
        }
        return new PBEKey(provider, (PBEKeySpec) keySpec, type);
    }

    /**
     * Returns a specification (key material) of the given key
     * in the requested format.
     *
     * @param key the key
     *
     * @param keySpecCl the requested format in which the key material shall be
     * returned
     *
     * @return the underlying key specification (key material) in the
     * requested format
     *
     * @exception InvalidKeySpecException if the requested key specification is
     * inappropriate for the given key, or the given key cannot be processed
     * (e.g., the given key has an unrecognized algorithm or format).
     */
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpecCl)
        throws InvalidKeySpecException {
        if ((key != null) && (key.getFormat() != null) && (key.getFormat().equalsIgnoreCase("RAW")) && (key.getEncoded() != null)) {
            // Check if requested key spec is amongst the valid ones
            if ((keySpecCl != null) && keySpecCl.isAssignableFrom(PBEKeySpec.class)) {
                byte[] passwdBytes = key.getEncoded();
                char[] passwdChars = new char[passwdBytes.length];
                for (int i=0; i < passwdChars.length; i++)
                    passwdChars[i] = (char) (passwdBytes[i] & 0x7f);
                PBEKeySpec ret = new PBEKeySpec(passwdChars);
                // password char[] was cloned in PBEKeySpec constructor,
                // so we can zero it out here
                java.util.Arrays.fill(passwdChars, '\0');
                java.util.Arrays.fill(passwdBytes, (byte) 0x00);
                return ret;
            } else {
                throw new InvalidKeySpecException("Invalid key spec");
            }
        } else {
            throw new InvalidKeySpecException("Invalid key "
                                            + "format/algorithm");
        }
    }

    /**
     * Translates a <code>SecretKey</code> object, whose provider may be
     * unknown or potentially untrusted, into a corresponding
     * <code>SecretKey</code> object of this key factory.
     *
     * @param key the key whose provider is unknown or untrusted
     *
     * @return the translated key
     *
     * @exception InvalidKeyException if the given key cannot be processed by
     * this key factory.
     */
    protected SecretKey engineTranslateKey(SecretKey key)
        throws InvalidKeyException {
        try {
            if ((key != null) && (key.getFormat() != null) && (key.getFormat().equalsIgnoreCase("RAW"))) {

                if (key instanceof com.ibm.crypto.plus.provider.PBEKey) {
                    return key;
                }

                // Convert key to spec
                PBEKeySpec pbeKeySpec = (PBEKeySpec) engineGetKeySpec
                    (key, PBEKeySpec.class);

                try {
                    return engineGenerateSecret(pbeKeySpec);
                } finally {
                    pbeKeySpec.clearPassword();
                }
            } else {
                throw new InvalidKeyException("Invalid key format/algorithm");
            }

        } catch (InvalidKeySpecException ikse) {
            throw new InvalidKeyException("Cannot translate key: "
                                          + ikse.getMessage());
        }
    }
}
