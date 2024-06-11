/*
 * Copyright IBM Corp. 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import ibm.jceplus.junit.openjceplusfips.Utils;
import junit.framework.Test;
import junit.framework.TestSuite;

public class TestSHA256Clone_SharedMD extends ibm.jceplus.junit.base.BaseTestSHA256Clone_SharedMD {


    //--------------------------------------------------------------------------
    //
    //
    static {
        Utils.loadProviderTestSuite();
    }

    //--------------------------------------------------------------------------
    //
    //
    public TestSHA256Clone_SharedMD() throws NoSuchAlgorithmException, NoSuchProviderException {
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
        TestSuite suite = new TestSuite(TestSHA256Clone_SharedMD.class);
        return suite;
    }
}


