/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;


import ibm.jceplus.junit.base.BaseTestHmacMD5Interop;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestHmacMD5InteropSunJCE extends BaseTestHmacMD5Interop {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestHmacMD5InteropSunJCE() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, Utils.PROVIDER_SunJCE);
    }

    public void testHmacMD5Interop() throws Exception {
        System.out.println("executing testHmacMD5Interop");
        BaseTestHmacMD5Interop bt = new BaseTestHmacMD5Interop(providerName, Utils.PROVIDER_SunJCE);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestHmacMD5InteropSunJCE.class
                        .getName()};
        junit.textui.TestRunner.main(nargs);
    }

}

