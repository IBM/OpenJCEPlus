/*
 * Copyright IBM Corp. 2023
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package com.ibm.crypto.plus.provider;

class AESUtils {

    private AESUtils() {}

    static final boolean isKeySizeValid(int keySize) {
        final int[] keySizes = AESConstants.AES_KEYSIZES;
        for (int index = 0; index < keySizes.length; index++) {
            if (keySize == keySizes[index]) {
                return true;
            }
        }
        return false;
    }

}
