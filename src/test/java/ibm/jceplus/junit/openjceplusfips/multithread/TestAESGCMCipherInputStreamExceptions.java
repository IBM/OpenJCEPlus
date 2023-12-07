/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestAESGCMCipherInputStreamExceptions;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestAESGCMCipherInputStreamExceptions
        extends BaseTestAESGCMCipherInputStreamExceptions {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestAESGCMCipherInputStreamExceptions() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplus.multithread.TestAESGCMCipherInputStreamExceptions.class
                        .getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testESGCMCipherInputStreamExceptions() throws Exception {
        System.out.println("executing testAESGCMCipherInputStreamExceptions");
        BaseTestAESGCMCipherInputStreamExceptions bt = new BaseTestAESGCMCipherInputStreamExceptions(
                providerName);
        bt.run();
    }
}

