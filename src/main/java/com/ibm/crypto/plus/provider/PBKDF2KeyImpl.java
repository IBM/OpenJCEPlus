/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import com.ibm.crypto.plus.provider.ock.OCKException;
import com.ibm.crypto.plus.provider.ock.PBKDF;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.lang.ref.Reference;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * This class represents a PBE key derived using PBKDF2 defined
 * in PKCS#5 v2.0. meaning that
 * 1) the password must consist of characters which will be converted
 *    to bytes using UTF-8 character encoding.
 * 2) salt, iteration count, and to be derived key length are supplied
 *
 * @author Valerie Peng
 *
 * See also same named class from OpenJDK. This class makes use of similar code.
 */
final class PBKDF2KeyImpl implements javax.crypto.interfaces.PBEKey {

    private static final long serialVersionUID = -2234868909660948157L;

    private OpenJCEPlusProvider provider = null;
    private char[] passwd;
    private byte[] salt;
    private final int iterCount;
    private byte[] key;
    private String prfAlgorithm;

    private static byte[] getPasswordBytes(char[] passwd) {
        CharBuffer cb = CharBuffer.wrap(passwd);
        ByteBuffer bb = UTF_8.encode(cb);

        int len = bb.limit();
        byte[] passwdBytes = new byte[len];
        bb.get(passwdBytes, 0, len);
        bb.clear().put(new byte[len]);

        return passwdBytes;
    }

    /**
     * Creates a PBE key from a given PBE key specification.
     *
     * @param keySpec the given PBE key specification
     * @param prfAlgo the given PBE key algorithm 
     */
    PBKDF2KeyImpl(OpenJCEPlusProvider provider, PBEKeySpec keySpec, String prfAlgo)
            throws InvalidKeySpecException {
        this.provider = provider;
        this.passwd = keySpec.getPassword();
        // Convert the password from char[] to byte[]
        byte[] passwdBytes = getPasswordBytes(this.passwd);

        try {
            this.salt = keySpec.getSalt();
            if (salt == null) {
                throw new InvalidKeySpecException("Salt not found");
            }
            this.iterCount = keySpec.getIterationCount();
            if (iterCount == 0) {
                throw new InvalidKeySpecException("Iteration count not found");
            } else if (iterCount < 0) {
                throw new InvalidKeySpecException("Iteration count is negative");
            }
            int keyLength = keySpec.getKeyLength();
            if (keyLength == 0) {
                throw new InvalidKeySpecException("Key length not found");
            } else if (keyLength < 0) {
                throw new InvalidKeySpecException("Key length is negative");
            }

            // Perform extra FIPS 140-3 related input checks.
            if (provider.getName().equalsIgnoreCase("OpenJCEPlusFIPS")) {
                // Key length must be higher then 112 bits.
                if (keyLength < 112) {
                    throw new InvalidKeySpecException("Key length must be 112 bits or higher when using the OpenJCEPlusFIPS provider.");
                }

                // Salt must be 128 bits.
                if (salt.length * 8 < 128) {
                    throw new InvalidKeySpecException("Salt must be 128 bits or higher when using the OpenJCEPlusFIPS provider.");
                }

                // Iteration count must be 1000 or higher.
                if (iterCount < 1000) {
                    throw new InvalidKeySpecException("Iteration count must be 1000 or higher when using the OpenJCEPlusFIPS provider.");
                }

                // Password length must be 10 characters or more.
                if (this.passwd.length < 10) {
                    throw new InvalidKeySpecException("Password must be 10 characters or higher when using the OpenJCEPlusFIPS provider.");
                }
            }

            this.prfAlgorithm = prfAlgo;

            // Convert key length to bytes and derive key using OCKC.
            try {
                this.key = PBKDF.PBKDF2derive(provider.getOCKContext(), this.prfAlgorithm,
                        passwdBytes, salt, iterCount, keyLength / 8);
            } catch (OCKException e) {
                throw new InvalidKeySpecException(
                        "Error while deriving PBKDF2 key from a given PBEKeySpec.", e);
            }

        } finally {
            Arrays.fill(passwdBytes, (byte) 0x00);
            if (key == null) {
                Arrays.fill(passwd, '\0');
            }
        }

        this.provider.registerCleanable(this, cleanOCKResources(this.key, this.passwd, this.salt));
    }

    public byte[] getEncoded() {
        try {
            return key.clone();
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    public String getAlgorithm() {
        return "PBKDF2With" + prfAlgorithm;
    }

    public int getIterationCount() {
        return iterCount;
    }

    public char[] getPassword() {
        try {
            return passwd.clone();
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    public byte[] getSalt() {
        return salt.clone();
    }

    public String getFormat() {
        return "RAW";
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    @Override
    public int hashCode() {
        int retval = 0;
        for (int i = 1; i < this.key.length; i++) {
            retval += this.key[i] * i;
        }
        return(retval ^= getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode());
    }

    public boolean equals(Object obj) {
        try {
            if (obj == this) {
                return true;
            }

            if (!(obj instanceof SecretKey)) {
                return false;
            }

            SecretKey that = (SecretKey) obj;

            if (!(that.getAlgorithm().equalsIgnoreCase(getAlgorithm()))) {
                return false;
            }
            if (!(that.getFormat().equalsIgnoreCase("RAW"))) {
                return false;
            }
            byte[] thatEncoded = that.getEncoded();
            boolean ret = MessageDigest.isEqual(key, thatEncoded);
            Arrays.fill(thatEncoded, (byte) 0x00);
            return ret;
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Replace the PBE key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws ObjectStreamException if a new object representing
     * this PBE key could not be created
     */
    private Object writeReplace() throws ObjectStreamException {
        try {
            return new JCEPlusKeyRep(JCEPlusKeyRep.Type.SECRET, getAlgorithm(), getFormat(), key, provider.getName());
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Restores the state of this object from the stream.
     * <p>
     * Deserialization of this class is not supported.
     *
     * @param  stream the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    private void readObject(ObjectInputStream stream) throws IOException, ClassNotFoundException {
        throw new InvalidObjectException("PBKDF2KeyImpl keys are not directly deserializable");
    }

    private Runnable cleanOCKResources(byte[] key, char[] passwd, byte[] salt){
        return() -> {
            try {
                if (key != null) {
                    java.util.Arrays.fill(key, (byte) 0x00);
                }
                if (passwd != null) {
                    java.util.Arrays.fill(passwd, '0');
                }
                if (salt != null) {
                    java.util.Arrays.fill(salt, (byte) 0x00);
                }
            } catch (Exception e){
                if (OpenJCEPlusProvider.getDebug() != null) {
                    OpenJCEPlusProvider.getDebug().println("An error occurred while cleaning : " + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
    }
}
