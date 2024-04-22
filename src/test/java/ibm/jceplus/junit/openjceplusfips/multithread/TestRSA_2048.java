/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSA;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSA_2048 extends BaseTestRSA {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    private static final int KEY_SIZE = 2048;

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA_2048() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, KEY_SIZE);
    }

    public void testRSA_2048() throws Exception {

        System.out.println("executing testRSA_2048");
        BaseTestRSA bt = new BaseTestRSA(providerName, KEY_SIZE);
        bt.run();

    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestRSA_2048.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }


}

