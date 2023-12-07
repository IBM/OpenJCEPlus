/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestRSAKey;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestRSAKey extends BaseTestRSAKey {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSAKey() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testRSAKey() throws Exception {

        System.out.println("executing testRSAKey");
        BaseTestRSAKey bt = new BaseTestRSAKey(providerName);
        bt.run();

    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestRSAKey.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

}

