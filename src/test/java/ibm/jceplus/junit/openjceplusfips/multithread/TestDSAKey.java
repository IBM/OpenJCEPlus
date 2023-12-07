/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestDSAKey;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestDSAKey extends BaseTestDSAKey {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestDSAKey() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //


    public void testDSAKey() throws Exception {

        System.out.println("executing testDSAKey");
        BaseTestDSAKey bt = new BaseTestDSAKey(providerName);
        bt.run();

    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplusfips.multithread.TestDSAKey.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }


}
