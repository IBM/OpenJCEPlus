/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
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
