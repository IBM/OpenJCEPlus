/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCMSameBuffer;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestAESGCMSameBuffer extends BaseTestAESGCMSameBuffer {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestAESGCMSameBuffer() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public static void main(String[] args) throws Exception {
        String[] nargs = {TestAESGCMSameBuffer.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCMSameBuffer() throws Exception {
        System.out.println("executing testAESGCMSameBuffer");
        BaseTestAESGCMSameBuffer bt = new BaseTestAESGCMSameBuffer(providerName);
        bt.run();
    }
}

