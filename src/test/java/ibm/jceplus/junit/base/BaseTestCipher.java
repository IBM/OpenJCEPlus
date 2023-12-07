/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.util.StringTokenizer;

public class BaseTestCipher extends BaseTest {
    //--------------------------------------------------------------------------
    //
    //
    public BaseTestCipher(String providerName) {
        super(providerName);
    }

    // --------------------------------------------------------------------------
    // This method is to check whether a transformation is valid for the cipher
    // but not supported by a given provider.
    //
    public boolean isTransformationValidButUnsupported(String transformation) {
        // Parse the transformation and check if the pieces are all supported
        //
        String[] parts = new String[3];
        int count = 0;
        StringTokenizer parser = new StringTokenizer(transformation, "/");

        try {
            while (parser.hasMoreTokens() && (count < parts.length)) {
                parts[count++] = parser.nextToken().trim();
            }

            if (count == 1) {
                return isAlgorithmValidButUnsupported(parts[0]);
            } else if (count == 3) {
                return isAlgorithmValidButUnsupported(parts[0])
                        || isModeValidButUnsupported(parts[1])
                        || isPaddingValidButUnsupported(parts[2]);
            }
        } catch (Exception e) {
        }

        return false;
    }

    // --------------------------------------------------------------------------
    // This method is to check whether an algorithm is valid for the cipher
    // but not supported by a given provider.
    //
    public boolean isAlgorithmValidButUnsupported(String algorithm) {
        return false;
    }

    // --------------------------------------------------------------------------
    // This method is to check whether a mode is valid for the cipher
    // but not supported by a given provider.
    //
    public boolean isModeValidButUnsupported(String mode) {
        return false;
    }

    // --------------------------------------------------------------------------
    // This method is to check whether a padding is valid for the cipher
    // but not supported by a given provider.
    //
    public boolean isPaddingValidButUnsupported(String padding) {
        return false;
    }
}

