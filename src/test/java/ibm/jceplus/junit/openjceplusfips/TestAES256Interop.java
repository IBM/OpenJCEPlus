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

public class TestAES256Interop extends ibm.jceplus.junit.base.BaseTestAESInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {

        Utils.loadProviderTestSuite();

        try {
            Utils.loadProviderBC();
        } catch (Exception e) {
            e.printStackTrace(System.out);
            System.exit(1);
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    private static final int KEY_SIZE = 256;

    //--------------------------------------------------------------------------
    //
    //
    public TestAES256Interop() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunJCE, KEY_SIZE);
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
        TestSuite suite = new TestSuite(TestAES256Interop.class);
        return suite;
    }
}

