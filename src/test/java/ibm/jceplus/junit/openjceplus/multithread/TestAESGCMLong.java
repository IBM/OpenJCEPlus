/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCMLong;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestAESGCMLong extends BaseTestAESGCMLong {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestAESGCMLong() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestAESGCMLong.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCMLong() throws Exception {
        BaseTestAESGCMLong bt = new BaseTestAESGCMLong(providerName);
        bt.run();
    }
}

