/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCM;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestAESGCM_128 extends BaseTestAESGCM {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    private static final int KEY_SIZE = 128;

    // --------------------------------------------------------------------------
    //
    //
    public TestAESGCM_128() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, KEY_SIZE);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplusfips.multithread.TestAESGCM_128.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAES_192() throws Exception {
        System.out.println("executing testAESGCM_128");
        BaseTestAESGCM bs = new BaseTestAESGCM(providerName, 128);
        bs.run();
    }

}
