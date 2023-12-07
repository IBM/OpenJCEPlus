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

public class TestAES_256 extends BaseTestAES {
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
    public TestAES_256() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);

    }

    // --------------------------------------------------------------------------
    //
    //
    public TestAES_256(int keySize) throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME, keySize);
    }

    public void testAES_256() throws Exception {
        BaseTestAES bs = new BaseTestAES(providerName, 256);
        System.out.println("executing testAES_256");
        bs.run();

    }

    public static void main(String[] args) {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestAES_256.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }


}
