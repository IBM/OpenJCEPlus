/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.openjceplus.multithread;


import ibm.jceplus.junit.base.BaseTestSHA512_224;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestSHA512_224 extends BaseTestSHA512_224 {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestSHA512_224() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testSHA512_224() throws Exception {
        System.out.println("executing testSHA512_224");
        BaseTestSHA512_224 bt = new BaseTestSHA512_224(providerName);

        bt.run();

    }

    public static void main(String[] args) {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestSHA512_224.class.getName()};
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
    //        TestSuite suite = new TestSuite(TestSHA512_224.class);
    //        return suite;
    //    }
}

