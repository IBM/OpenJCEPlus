/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

abstract public class Utils extends ibm.jceplus.junit.base.BaseUtils {


    public static final String TEST_SUITE_PROVIDER_NAME = PROVIDER_OpenJCEPlus;


    public static java.security.Provider loadProviderTestSuite() {
        if (System.getProperty("os.name").equals("z/OS")) {
            Utils.PROVIDER_SunEC = "BC"; //jpf SunEC doesn't have the necessary EC algorithms use BouncyCastle instead "SunEC";
        }

        try {
            return loadProviderOpenJCEPlus();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
            return null;
        }
    }
}

