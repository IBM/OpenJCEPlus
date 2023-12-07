/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestDESede extends ibm.jceplus.junit.base.BaseTestDESede {

    private static final boolean PROVIDER_SUPPORTS_ENCRYPT = true;

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestDESede() {
        super(Utils.TEST_SUITE_PROVIDER_NAME, PROVIDER_SUPPORTS_ENCRYPT);
    }

    //--------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    //--------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestDESede.class);
        return suite;
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

