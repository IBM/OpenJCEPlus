/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import junit.framework.Test;
import junit.framework.TestSuite;

public class TestIsAssignableFromOrder extends ibm.jceplus.junit.base.BaseTestIsAssignableFromOrder {

    // --------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    // --------------------------------------------------------------------------
    //
    //
    public TestIsAssignableFromOrder() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    // --------------------------------------------------------------------------
    //
    //
    public static void main(String[] args) throws Exception {
        junit.textui.TestRunner.run(suite());
    }

    // --------------------------------------------------------------------------
    //
    //
    public static Test suite() {
        TestSuite suite = new TestSuite(TestIsAssignableFromOrder.class);
        return suite;
    }
}
