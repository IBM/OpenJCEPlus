/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestXDH;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestXDH extends BaseTestXDH {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestXDH() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
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
    // TestSuite suite = new TestSuite(TestXDH.class);
    // return suite;
    // }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestXDH.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testXDH() throws Exception {
        System.out.println("exuting testXDH");
        BaseTestXDH bt = new BaseTestXDH(providerName);
        bt.run();
    }

}
