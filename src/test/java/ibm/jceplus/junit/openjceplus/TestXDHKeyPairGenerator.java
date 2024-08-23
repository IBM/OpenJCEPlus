/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplus;

import java.security.KeyPairGenerator;
import junit.framework.Test;
import junit.framework.TestSuite;
import org.junit.Before;

public class TestXDHKeyPairGenerator extends ibm.jceplus.junit.base.BaseTestXDHKeyPairGenerator {

    KeyPairGenerator kpg = null;
    KeyPairGenerator kpgc = null;

    @Before
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        kpg = KeyPairGenerator.getInstance("XDH", providerName);
        kpgc = KeyPairGenerator.getInstance("XDH", providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestXDHKeyPairGenerator() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
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
        TestSuite suite = new TestSuite(TestXDHKeyPairGenerator.class);
        return suite;
    }
}
