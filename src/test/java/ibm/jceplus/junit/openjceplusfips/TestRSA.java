/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

import ibm.jceplus.junit.base.BaseTest;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestRSA extends BaseTest {

    protected int specifiedKeySize = 0;
    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestRSA(int keySize) throws Exception {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
        this.specifiedKeySize = keySize;
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
        TestSuite suite = new TestSuite(TestRSA.class);
        return suite;
    }

        // --------------------------------------------------------------------------
    // This method is to check whether OpenJCEPlusFIPS can throw exception with RSA cipher 
    //
    public static void testLoadRSACipher() throws Exception{
        try {
            Cipher.getInstance("RSA", Utils.TEST_SUITE_PROVIDER_NAME);
        } catch (NoSuchAlgorithmException nsae) {
            assertEquals("No such algorithm: RSA", nsae.getMessage());
            return;
        }
    }
}

