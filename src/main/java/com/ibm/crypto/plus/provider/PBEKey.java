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
import java.security.MessageDigest;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;

final class PBEKey implements SecretKey {

    private static final long serialVersionUID = 9223372036854775807L;

    private byte[] key;

    private final String type;

    private boolean destroyed = false;

    private OpenJCEPlusProvider provider = null;

    /**
     * Creates a PBE key from a given PBE key specification.
     *
     * @param keytype the given PBE key specification
     */
    PBEKey(OpenJCEPlusProvider provider, PBEKeySpec keySpec, String keytype) throws InvalidKeySpecException {
        char[] passwd = keySpec.getPassword();

        if (passwd == null || passwd.length == 0) {
            // Should allow an empty password.
            passwd = new char[0];
        }

        if (provider == null) {
            throw new IllegalArgumentException("provider is null");
        }

        for (char c : passwd) {
            if (Character.isISOControl(c))
                throw new InvalidKeySpecException("Invalid Password.");
        }

        this.key = PBEUtil.encodePassword(passwd);
        Arrays.fill(passwd, '\0');
        type = keytype;
        this.provider = provider;

        this.provider.registerCleanable(this, cleanOCKResources(this.key));
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

    @Override
    public int hashCode() {
        try {
            int retval = 0;
            for (int i = 1; i < this.key.length; i++) {
                retval += this.key[i] * i;
            }
            return(retval ^ getAlgorithm().toLowerCase(Locale.ENGLISH).hashCode());
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

            SecretKey that;
            if (!(obj instanceof SecretKey))
                return false;
            that = (SecretKey) obj;

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

    @Override
    public void destroy() {
        if (this.key != null) {
            Arrays.fill(this.key, (byte) 0x00);
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
    private Object writeReplace() throws java.io.ObjectStreamException {
        try {
            return new JCEPlusKeyRep(JCEPlusKeyRep.Type.SECRET, 
                getAlgorithm(), getFormat(), getEncoded(), provider.getName());
        } finally {
            // prevent this from being cleaned for the above block
            Reference.reachabilityFence(this);
        }
    }


    private Runnable cleanOCKResources(byte[] key) {
        return() -> {
            try {
                if (key != null) {
                    Arrays.fill(key, (byte) 0x00);
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
