/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;


import ibm.jceplus.junit.base.BaseTestHmacSHA256Interop;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestHmacSHA256InteropSunJCE extends BaseTestHmacSHA256Interop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestHmacSHA256InteropSunJCE() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunJCE);
    }

    public void testHmacSHA256Interop() throws Exception {
        System.out.println("executing testHmacSHA256Interop");
        BaseTestHmacSHA256Interop bt = new BaseTestHmacSHA256Interop(providerName,
                Utils.PROVIDER_SunJCE);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {
                ibm.jceplus.junit.openjceplus.multithread.TestHmacSHA256InteropSunJCE.class
                        .getName()};
        junit.textui.TestRunner.main(nargs);
    }
}

