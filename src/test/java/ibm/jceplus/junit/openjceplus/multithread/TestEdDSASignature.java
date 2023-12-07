/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestEdDSASignature;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestEdDSASignature extends BaseTestEdDSASignature {
    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestEdDSASignature() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testEdDSASignature() throws Exception {
        System.out.println("executing EdDSASignature");
        BaseTestEdDSASignature bt = new BaseTestEdDSASignature(providerName);
        bt.run();
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {
                ibm.jceplus.junit.openjceplus.multithread.TestEdDSASignature.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }
}
