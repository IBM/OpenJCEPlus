/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestXDHMultiParty;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestXDHMultiParty extends ibm.jceplus.junit.base.BaseTestXDHMultiParty {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestXDHMultiParty() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplus.multithread.TestXDHMultiParty.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testECDSASignature() throws Exception {
        System.out.println("executing TestXDHKeyImport");
        BaseTestXDHMultiParty bt = new BaseTestXDHMultiParty(providerName);
        bt.run();
    }

}
