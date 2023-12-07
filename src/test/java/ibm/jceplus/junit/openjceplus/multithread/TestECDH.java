/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestECDH;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestECDH extends BaseTestECDH {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestECDH() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
        isMulti = true;
    }

    // --------------------------------------------------------------------------
    //
    //
    // public static void main(String[] args) throws Exception {
    // junit.textui.TestRunner.run(suite());
    // }
    //
    // //--------------------------------------------------------------------------
    // //
    // //
    // public static void testECDH () throws Exception {
    //
    // junit.textui.TestRunner.run(suite());
    // }
    //
    // //--------------------------------------------------------------------------
    // //
    // //
    // public static Test suite() {
    // TestSuite suite = new TestSuite(TestECDH.class);
    // return suite;
    // }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestECDH.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testECDH() throws Exception {
        System.out.println("executing testECDH");
        BaseTestECDH bt = new BaseTestECDH(providerName);
        bt.run();
    }

}
