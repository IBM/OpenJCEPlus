/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestHmacMD5;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestHmacMD5 extends BaseTestHmacMD5 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestHmacMD5() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }



    public void testHmacMD5() throws Exception {
        System.out.println("executing testHmacMD5");
        BaseTestHmacMD5 bt = new BaseTestHmacMD5(providerName);
        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestHmacMD5.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

}

