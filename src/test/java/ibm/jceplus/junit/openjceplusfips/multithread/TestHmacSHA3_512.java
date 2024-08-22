/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestHmacSHA3_512;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestHmacSHA3_512 extends ibm.jceplus.junit.base.BaseTestHmacSHA3_512 {

    static {
        Utils.loadProviderTestSuite();
    }

    public TestHmacSHA3_512() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testHmacSHA3_512() throws Exception {
        System.out.println("executing testHmacSHA3_512");
        BaseTestHmacSHA3_512 bt = new BaseTestHmacSHA3_512(providerName);
        bt.run();
    }
}
