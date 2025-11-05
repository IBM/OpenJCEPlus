/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * This class represents a DES-EDE key.
 */
final class DESedeKey implements SecretKey, Destroyable {

    static final long serialVersionUID = -262568625658400172L;

    private byte[] key;

    private transient boolean destroyed = false;

    private OpenJCEPlusProvider provider = null;

    /**
     * Creates a DES-EDE key from a given key.
     *
     * @param key the given key
     *
     * @exception InvalidKeyException if the given key has a wrong size
     */
    DESedeKey(OpenJCEPlusProvider provider, byte[] key) throws InvalidKeyException {
        if ((key == null) || (key.length < DESedeKeySpec.DES_EDE_KEY_LEN)) {
            throw new InvalidKeyException("Wrong key size");
        }

        this.provider = provider;
        this.key = new byte[DESedeKeySpec.DES_EDE_KEY_LEN];
        System.arraycopy(key, 0, this.key, 0, DESedeKeySpec.DES_EDE_KEY_LEN);
        DESedeKeyGenerator.setParityBit(key, 0);
        DESedeKeyGenerator.setParityBit(key, 8);
        DESedeKeyGenerator.setParityBit(key, 16);
    }

    @Override
    public String getAlgorithm() {
        checkDestroyed();
        return "DESede";
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
        return this.key.clone();
    }

    /**
     * Calculates a hash code value for the object.
     * Objects that are equal will also have the same hashcode.
     */
    @Override
    public int hashCode() {
        checkDestroyed();

        SecretKeySpec keySpec = new SecretKeySpec(this.key, getAlgorithm());
        return keySpec.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        checkDestroyed();

        if (this == obj)
            return true;

        if (!(obj instanceof SecretKey))
            return false;

        String thatAlg = ((SecretKey) obj).getAlgorithm();
        if (!(thatAlg.equalsIgnoreCase("DESede")) && !(thatAlg.equalsIgnoreCase("TripleDES")))
            return false;

        byte[] thatKey = ((SecretKey) obj).getEncoded();
        boolean ret = java.util.Arrays.equals(this.key, thatKey);
        java.util.Arrays.fill(thatKey, (byte) 0x00);
        return ret;
    }

    /**
     * readObject is called to restore the state of this key from
     * a stream.
     */
    private void readObject(java.io.ObjectInputStream s)
            throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();
        key = key.clone();
    }

    /**
     * Replace the DESede key to be serialized.
     *
     * @return the standard KeyRep object to be serialized
     *
     * @throws java.io.ObjectStreamException if a new object representing
     * this DESede key could not be created
     */
    private Object writeReplace() throws java.io.ObjectStreamException {
        checkDestroyed();
        return new JCEPlusKeyRep(JCEPlusKeyRep.Type.SECRET, getAlgorithm(), getFormat(), getEncoded(), provider.getName());
    }

    /**
     * Destroys this key. A call to any of its other methods after this
     * will cause an  IllegalStateException to be thrown.
     *
     * @throws DestroyFailedException if some error occurs while destroying
     * this key.
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

    /** Determines if this key has been destroyed.*/
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
     * This function zeroizes the key so that it isn't in memory when GC is done.
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
