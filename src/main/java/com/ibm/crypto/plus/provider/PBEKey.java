/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.lang.ref.Reference;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import sun.security.util.PBEUtil;


/**
 * This class represents a PBE key.
 *
 * @author Jan Luehe
 *
 */
final class PBEKey implements SecretKey {

    @java.io.Serial
    private static final long serialVersionUID = -2234768909660948176L;

    private byte[] key;

    private final String type;

    private boolean destroyed = false;

    /**
     * Creates a PBE key from a given PBE key specification.
     *
     * @param keytype the given PBE key specification
     */
    PBEKey(PBEKeySpec keySpec, String keytype) throws InvalidKeySpecException {
        char[] passwd = keySpec.getPassword();

        for (char c : passwd) {
            if (Character.isISOControl(c))
                throw new InvalidKeySpecException("Invalid Password.");
        }

        if (passwd == null || passwd.length == 0) {
            // Should allow an empty password.
            passwd = new char[0];
        }

        this.key = PBEUtil.encodePassword(passwd);
        Arrays.fill(passwd, '\0');
        type = keytype;

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
        return type;
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
        try {
            return Arrays.hashCode(this.key)
                    ^ getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode();
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    @Override
    public boolean equals(Object obj) {
        try {
            if (obj == this)
                return true;

            if (!(obj instanceof SecretKey that))
                return false;

            // destroyed keys are considered different
            if (isDestroyed() || that.isDestroyed()) {
                return false;
            }

            if (!(that.getAlgorithm().equalsIgnoreCase(type)))
                return false;

            byte[] thatEncoded = that.getEncoded();
            boolean ret = MessageDigest.isEqual(this.key, thatEncoded);
            Arrays.fill(thatEncoded, (byte) 0x00);
            return ret;
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Clears the internal copy of the key.
     *
     */
    @Override
    public void destroy() {
        if (this.key != null) {
            Arrays.fill(this.key, (byte) 0);
            destroyed = true; 
        }
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    /**
     * Restores the state of this object from the stream.
     *
     * @param  s the {@code ObjectInputStream} from which data is read
     * @throws IOException if an I/O error occurs
     * @throws ClassNotFoundException if a serialized class cannot be loaded
     */
    @java.io.Serial
    private void readObject(java.io.ObjectInputStream s)
         throws IOException, ClassNotFoundException
    {
        s.defaultReadObject();
        if (key == null) {
            throw new InvalidObjectException(
                    "PBEKey couldn't be deserialized");
        }
        byte[] temp = key;
        key = temp.clone();
        Arrays.fill(temp, (byte) 0x00);

        // Accept "\0" to signify "zero-length password with no terminator".
        if (!(key.length == 1 && key[0] == 0)) {
            for (int i = 0; i < key.length; i++) {
                if ((key[i] < '\u0020') || (key[i] > '\u007E')) {
                    throw new InvalidObjectException(
                            "PBEKey had non-ASCII chars");
                }
            }
        }
    }


    /**
     * Replace the PBE key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing
     * this PBE key could not be created
     */
    @java.io.Serial
    private Object writeReplace() throws java.io.ObjectStreamException {
        try {
            return new KeyRep(KeyRep.Type.SECRET,
                    getAlgorithm(),
                    getFormat(),
                    key);
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }

    /**
     * Cleans all sensitive information associated with this instance.
     */
    protected void finalize() throws Throwable {
        try {
            destroy();
        } finally {
            super.finalize();
        }
    }
}
