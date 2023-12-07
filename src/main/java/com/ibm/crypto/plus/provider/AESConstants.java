/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
