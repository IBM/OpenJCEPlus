/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

/**
 * This class defines the constants used by the AES algorithm
 * implementation.
 */

interface AESConstants {

    // AES block size in bytes.
    public static final int AES_BLOCK_SIZE = 16;

    // Valid AES key sizes in bytes. 
    // NOTE: The values need to be listed in an *increasing* order
    // since DHKeyAgreement depends on this fact.
    public static final int[] AES_KEYSIZES = {16, 24, 32};
}
