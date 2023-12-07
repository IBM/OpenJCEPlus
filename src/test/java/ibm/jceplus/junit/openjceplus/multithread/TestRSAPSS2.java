/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestRSAPSS2;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestRSAPSS2 extends ibm.jceplus.junit.base.BaseTestRSAPSS2 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAPSS2() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestRSAPSS2.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testRSAPSS2() throws Exception {
        System.out.println("executing testRSAPSS2");
        BaseTestRSAPSS2 bt = new BaseTestRSAPSS2(providerName);
        bt.run();
    }

}

