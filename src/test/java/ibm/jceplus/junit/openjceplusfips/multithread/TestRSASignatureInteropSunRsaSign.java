/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestRSASignatureInterop;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestRSASignatureInteropSunRsaSign extends BaseTestRSASignatureInterop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSASignatureInteropSunRsaSign() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunRsaSign, 2048);
    }

    //--------------------------------------------------------------------------
    //
    //

    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestRSASignatureInteropSunRsaSign.class
                        .getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testRSASignatureInteropSunRsaSign() throws Exception {
        System.out.println("executing testRSASignatureInteropSunRsaSign");
        BaseTestRSASignatureInterop bt = new BaseTestRSASignatureInterop(providerName,
                Utils.PROVIDER_SunRsaSign);
        bt.run();
    }
}

