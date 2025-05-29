/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.security.internal.spec;

import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * This is here for easier compatability with OpenJDK 21 and above.
 * 
 * This is a KeySpec that is used to specify a key by its byte array implementation. Since the
 * new PQC algs the bytes are defined as byte arrays.
 */
public class RawKeySpec implements KeySpec {
    private byte[] keyBytes = null;
    /**
     * @param key contains the key as a byte array
     */
    public RawKeySpec(byte[] key) {
        keyBytes = key.clone();
    }

    /**
     * @return a copy of the key bits
     */
    public byte[] getKeyArr() {
        return keyBytes.clone();
    }

    protected void finalize() throws Throwable {
        if (keyBytes != null) {
            Arrays.fill(keyBytes,0,keyBytes.length, (byte)0);
        }
    }
}
