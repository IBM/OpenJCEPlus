/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCMWithByteBuffer;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestAESGCMWithByteBuffer extends BaseTestAESGCMWithByteBuffer {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestAESGCMWithByteBuffer() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public static void main(String[] args) throws Exception {
        String[] nargs = {TestAESGCMWithByteBuffer.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAESGCMWithByteBuffer() throws Exception {
        System.out.println("executing testAESGCMWithByteBuffer");
        BaseTestAESGCMWithByteBuffer bt = new BaseTestAESGCMWithByteBuffer(providerName);
        bt.run();
    }
}

