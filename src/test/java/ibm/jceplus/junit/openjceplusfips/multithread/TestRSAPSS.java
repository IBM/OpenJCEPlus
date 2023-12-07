/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSAPSS;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSAPSS extends ibm.jceplus.junit.base.BaseTestRSAPSS {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAPSS() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplusfips.multithread.TestRSAPSS.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testRSAPSS() throws Exception {
        System.out.println("executing testRSAPSS");
        BaseTestRSAPSS bt = new BaseTestRSAPSS(providerName);
        bt.run();
    }

}

