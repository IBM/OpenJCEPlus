/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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

