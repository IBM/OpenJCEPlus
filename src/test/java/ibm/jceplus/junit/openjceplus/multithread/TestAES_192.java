/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestAES;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestAES_192 extends ibm.jceplus.junit.base.BaseTestAES {
    static boolean first = true;
    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    private static final int KEY_SIZE = 192;

    // --------------------------------------------------------------------------
    //
    //
    public TestAES_192() throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, KEY_SIZE);

    }

    // --------------------------------------------------------------------------
    //
    //
    public TestAES_192(int keySize) throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, keySize);
    }


    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestAES_192.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testAES_192() throws Exception {
        System.out.println("executing testAES_192");
        ibm.jceplus.junit.base.BaseTestAES bs = new BaseTestAES(providerName, 192);
        bs.run();
    }

}
