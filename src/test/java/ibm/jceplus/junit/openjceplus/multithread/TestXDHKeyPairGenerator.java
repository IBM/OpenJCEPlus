/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestXDHKeyPairGenerator;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestXDHKeyPairGenerator extends ibm.jceplus.junit.base.BaseTestXDHKeyPairGenerator {


    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestXDHKeyPairGenerator() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplus.multithread.TestXDHKeyPairGenerator.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testXDH() throws Exception {
        System.out.println("exuting testXDH");
        BaseTestXDHKeyPairGenerator bt = new BaseTestXDHKeyPairGenerator(providerName);
        bt.run();
    }
}
