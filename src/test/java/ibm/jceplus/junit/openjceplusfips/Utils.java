/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

abstract public class Utils extends ibm.jceplus.junit.base.BaseUtils {

    public static final String TEST_SUITE_PROVIDER_NAME = PROVIDER_OpenJCEPlusFIPS;

    public static java.security.Provider loadProviderTestSuite() {
        try {
            return loadProviderOpenJCEPlusFIPS();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
            return null;
        }
    }
}

