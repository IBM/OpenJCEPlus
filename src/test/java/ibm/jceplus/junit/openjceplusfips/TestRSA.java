/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSA extends ibm.jceplus.junit.base.BaseTestRSA {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA(int keySize) throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, keySize);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestRSA.class);
        return suite;
    }

    // --------------------------------------------------------------------------
    // This method is to check whether an algorithm is valid for the cipher
    // but not supported by a given provider.
    //
    @Override
    public boolean isAlgorithmValidButUnsupported(String algorithm) {
        if (algorithm.equalsIgnoreCase("RSAwithNoPad") || algorithm.equalsIgnoreCase("RSAforSSL")) {
            return true;
        }

        return super.isAlgorithmValidButUnsupported(algorithm);
    }

    // --------------------------------------------------------------------------
    // This method is to check whether a padidng is valid for the cipher
    // but not supported by a given provider.
    //
    @Override
    public boolean isPaddingValidButUnsupported(String padding) {
        if (padding.equalsIgnoreCase("ZeroPadding")
                || padding.equalsIgnoreCase("OAEPWithSHA-224AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-256AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-384AndMGF1Padding")
                || padding.equalsIgnoreCase("OAEPWithSHA-512AndMGF1Padding")) {
            return true;
        }

        return super.isPaddingValidButUnsupported(padding);
    }
}

