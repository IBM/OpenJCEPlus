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

public class TestRSA_4096 extends TestRSA {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    private static final int KEY_SIZE = 4096;

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA_4096() throws Exception {
        super(KEY_SIZE);
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
        TestSuite suite = new TestSuite(TestRSA_4096.class);
        return suite;
    }
}

