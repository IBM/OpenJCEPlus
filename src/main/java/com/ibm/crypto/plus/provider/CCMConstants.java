/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package com.ibm.crypto.plus.provider;

/**
 * Interface for CCM constants.
 *
 */
interface CCMConstants {

    public int DEFAULT_AES_CCM_TAG_LENGTH = 96; // default AES/CCM tag length in bits

    public int DEFAULT_AES_CCM_IV_LENGTH = 13; // default AES/CCM IV length in bytes

}
