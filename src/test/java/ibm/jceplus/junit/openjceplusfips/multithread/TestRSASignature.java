/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSASignature;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSASignature extends BaseTestRSASignature {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSASignature() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, 2048);
    }

    public void testRSASignature() throws Exception {
        System.out.println("executing testRSASignature");
        BaseTestRSASignature bt = new BaseTestRSASignature(providerName);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignature.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }
    //--------------------------------------------------------------------------
    //
    //

}

