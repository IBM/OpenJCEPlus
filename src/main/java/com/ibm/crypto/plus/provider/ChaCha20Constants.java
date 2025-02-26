/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * This class defines the constants used by the ChaCha20 algorithm
 * implementation.
 */

public interface ChaCha20Constants {

    // ChaCha20 block size in bytes.
    public static final int ChaCha20_BLOCK_SIZE = 0;

    // ChaCha20 key size in bytes.
    public static final int ChaCha20_KEY_SIZE = 32;

    // ChaCha20 counter size in bytes.
    public static final int ChaCha20_COUNTER_SIZE = 4;

    // ChaCha20 nonce size in bytes.
    public static final int ChaCha20_NONCE_SIZE = 12;

    // ChaCha20 IV size in bytes.
    public static final int ChaCha20_IV_SIZE = ChaCha20_COUNTER_SIZE + ChaCha20_NONCE_SIZE;

}
