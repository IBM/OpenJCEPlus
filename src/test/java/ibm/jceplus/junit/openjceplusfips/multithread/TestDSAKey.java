/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestDSAKey;
import ibm.jceplus.junit.openjceplusfips.Utils;
import org.junit.jupiter.api.Disabled;

public class TestDSAKey extends BaseTestDSAKey {

    static {
        Utils.loadProviderTestSuite();
    }

    public TestDSAKey() {
        super(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @Disabled("DSA key generation is not available in FIPS mode.")
    @Override
    public void testDSAKeyGen_1024() throws Exception {}

    @Disabled("DSA key generation is not available in FIPS mode.")
    @Override
    public void testDSAKeyGen_2048() throws Exception {}

    @Disabled("DSA algorithm parameters are not available in FIPS mode.")
    @Override
    public void testDSAKeyGenFromParams_1024() throws Exception {}
}
