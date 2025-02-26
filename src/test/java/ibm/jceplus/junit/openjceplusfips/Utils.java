/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
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

