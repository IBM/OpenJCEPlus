/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * This class represents an ChaCha20 key.
 */
final class ChaCha20Key implements SecretKey, Destroyable, ChaCha20Constants {

    static final long serialVersionUID = -8899864838936117258L;

    private byte[] key;

    private transient boolean destroyed = false;

    /**
     * Create an ChaCha20 key from a given key
     *
     * @param key
     *            the given key
     *
     * @exception InvalidKeyException
     *                if the given key has wrong size
     */
    public ChaCha20Key(byte[] key) throws InvalidKeyException {

        if ((key == null) || (key.length != ChaCha20_KEY_SIZE)) {
            throw new InvalidKeyException("Wrong key size");
        }

        this.key = new byte[key.length];
        System.arraycopy(key, 0, this.key, 0, key.length);
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return "ChaCha20";
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return "RAW";
    }

    @Override
    public synchronized byte[] getEncoded() {
        checkDestroyed();

        // Return a copy of the key, rather than a reference,
        // so that the key data cannot be modified from outside
        return (byte[]) this.key.clone();
    }

    /**
     * Calculates a hash code value for the object. Objects that are equal will
     * also have the same hashcode.
     */
    @Override
    public int hashCode() {
        checkDestroyed();

        int retval = 0;
        for (int i = 1; i < this.key.length; i++) {
            retval += this.key[i] * i;
        }
        return (retval ^= "ChaCha20".hashCode());
    }

    @Override
    public boolean equals(Object obj) {
        checkDestroyed();

        if (this == obj)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        String thatAlg = ((SecretKey) obj).getAlgorithm();
        if (!(thatAlg.equalsIgnoreCase("ChaCha20")))
            return false;

        byte[] thatKey = ((SecretKey) obj).getEncoded();
        boolean ret = java.util.Arrays.equals(this.key, thatKey);
        java.util.Arrays.fill(thatKey, (byte) 0x00);
        return ret;
    }

    /**
     * readObject is called to restore the state of this key from a stream.
     */
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();
        key = key.clone();
    }

    /**
     * Replace the ChaCha20 key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException
     *             if a new object representing this ChaCha20 key could not be
     *             created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new KeyRep(KeyRep.Type.SECRET, getAlgorithm(), getFormat(), getEncoded());
    }

    /**
     * Destroys this key. A call to any of its other methods after this will
     * cause an IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException
     *             if some error occurs while destroying this key.
     */
    @Override
    public void destroy() throws DestroyFailedException {
        if (!destroyed) {
            destroyed = true;
            if (key != null) {
                Arrays.fill(key, (byte) 0x00);
            }
        }
    }

    /** Determines if this key has been destroyed. */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("This key is no longer valid");
        }
    }

    /**
     * This function zeroizes the key so that it isn't in memory when GC is
     * done.
     */
    @Override
    protected void finalize() throws Throwable {
        try {
            synchronized (this) {
                if (this.key != null) {
                    Arrays.fill(this.key, (byte) 0x00);
                    this.key = null;
                }
            }
        } finally {
            super.finalize();
        }
    }
}
