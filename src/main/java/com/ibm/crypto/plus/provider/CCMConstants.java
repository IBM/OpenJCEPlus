/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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
