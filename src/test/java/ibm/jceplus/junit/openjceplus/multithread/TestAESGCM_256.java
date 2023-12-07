/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCM;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestAESGCM_256 extends BaseTestAESGCM {

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
    public TestAESGCM_256() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, KEY_SIZE);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestAESGCM_256.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCM_256() throws Exception {
        System.out.println("executing testAESGCM_256");
        BaseTestAESGCM bs = new BaseTestAESGCM(providerName, 256);
        bs.run();
    }

}
