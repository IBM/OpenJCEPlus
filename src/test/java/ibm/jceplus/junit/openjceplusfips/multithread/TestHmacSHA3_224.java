/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestHmacSHA3_224;
import ibm.jceplus.junit.openjceplus.Utils;

public class TestHmacSHA3_224 extends ibm.jceplus.junit.base.BaseTestHmacSHA3_224 {

    static {
        Utils.loadProviderTestSuite();
    }

    public TestHmacSHA3_224() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    public void testHmacSHA3_224() throws Exception {
        System.out.println("executing testHmacSHA3_224");
        BaseTestHmacSHA3_224 bt = new BaseTestHmacSHA3_224(providerName);
        bt.run();
    }
}
