/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus.multithread;

import ibm.jceplus.junit.base.BaseTestDESede;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestDESede extends BaseTestDESede {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestDESede() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        String[] nargs = {ibm.jceplus.junit.openjceplus.multithread.TestDESede.class.getName()};
        junit.textui.TestRunner.main(nargs);
    }

    // --------------------------------------------------------------------------
    //
    //
    public void testDESede() throws Exception {
        System.out.println("executing testDESede");
        BaseTestDESede bt = new BaseTestDESede(providerName);
        bt.run();
    }


    // --------------------------------------------------------------------------
    // This method is to check whether a mode is valid for the cipher
    // but not supported by a given provider.
    //
    @Override
    public boolean isModeValidButUnsupported(String mode) {
        if (mode.equalsIgnoreCase("CFB") || mode.equalsIgnoreCase("CFB64")
                || mode.equalsIgnoreCase("OFB")) {
            return true;
        }

        return super.isModeValidButUnsupported(mode);
    }
}
