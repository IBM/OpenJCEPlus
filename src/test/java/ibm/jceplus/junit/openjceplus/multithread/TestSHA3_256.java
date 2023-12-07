/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.openjceplus.Utils;

public class TestSHA3_256 extends ibm.jceplus.junit.base.BaseTestSHA3_256KAT {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestSHA3_256() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testSHA3_256() throws Exception {
        System.out.println("executing testSHA3_256");
        ibm.jceplus.junit.base.BaseTestSHA3_256KAT bt = new ibm.jceplus.junit.base.BaseTestSHA3_256KAT(
                providerName);

        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestSHA3_256.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }
}

