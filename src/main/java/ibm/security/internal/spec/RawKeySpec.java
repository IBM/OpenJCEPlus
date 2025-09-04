/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.security.internal.spec;

import java.security.spec.KeySpec;
<<<<<<< HEAD
=======
import java.util.Arrays;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210

/**
 * This is here for easier compatability with OpenJDK 21 and above.
 * 
 * This is a KeySpec that is used to specify a key by its byte array implementation. Since the
 * new PQC algs the bytes are defined as byte arrays.
 */
public class RawKeySpec implements KeySpec {
<<<<<<< HEAD
    private final byte[] keyBytes;
=======
    private byte[] keyBytes = null;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
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
<<<<<<< HEAD
=======

    protected void finalize() throws Throwable {
        if (keyBytes != null) {
            Arrays.fill(keyBytes,0,keyBytes.length, (byte)0);
        }
    }
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
}
