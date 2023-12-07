/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestDSASignatureInterop;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestDSASignatureInteropSUN extends BaseTestDSASignatureInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestDSASignatureInteropSUN() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SUN);
    }

    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestDSASignatureInteropSUN.class
                        .getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDSASignatureInteropSUN() throws Exception {
        System.out.println("executing testDSASignatureInteropSUN");
        BaseTestDSASignatureInterop bt = new BaseTestDSASignatureInterop(providerName,
                Utils.PROVIDER_SUN);
        bt.run();
    }


}

