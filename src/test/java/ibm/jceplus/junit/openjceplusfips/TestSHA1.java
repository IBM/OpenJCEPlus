/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import static org.junit.jupiter.api.Assertions.assertEquals;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Cipher;
import ibm.jceplus.junit.base.BaseTest;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestSHA1 extends BaseTest {

    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestSHA1() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public static void testSHA1Cipher() throws Exception {
        try {
            Cipher.getInstance("SHA1", Utils.TEST_SUITE_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException nsae) {
            assertEquals("No such algorithm: SHA1", nsae.getMessage());
        }
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
        TestSuite suite = new TestSuite(TestSHA1.class);
        return suite;
    }
}

