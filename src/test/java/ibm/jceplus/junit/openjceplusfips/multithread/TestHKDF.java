/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestHKDF;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestHKDF extends BaseTestHKDF {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestHKDF() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplusfips.multithread.TestHKDF.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testHKDF() throws Exception {
        System.out.println("executing testHKDF");
        BaseTestHKDF bt = new BaseTestHKDF(providerName);
        bt.run();
    }
}

