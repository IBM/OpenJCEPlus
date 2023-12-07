/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;


import ibm.jceplus.junit.base.BaseTestSHA512;
import ibm.jceplus.junit.openjceplusfips.Utils;

public class TestSHA512 extends BaseTestSHA512 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestSHA512() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testSHA512() throws Exception {
        System.out.println("executing testSHA512");
        BaseTestSHA512 bt = new BaseTestSHA512(providerName);

        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {ibm.jceplus.junit.openjceplusfips.multithread.TestSHA512.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    //--------------------------------------------------------------------------
    //
    //
    //    public static void main(String[] args) throws Exception {
    //        junit.textui.TestRunner.run(suite());
    //    }
    //
    //    //--------------------------------------------------------------------------
    //    //
    //    //
    //    public static Test suite() {
    //        TestSuite suite = new TestSuite(TestSHA512.class);
    //        return suite;
    //    }
}

