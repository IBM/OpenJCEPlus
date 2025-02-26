/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestRSATypeCheckDisabled;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestRSATypeCheckDisabled extends BaseTestRSATypeCheckDisabled {

    @BeforeAll
    public void beforeAll() {
        System.setProperty("com.ibm.crypto.provider.DoRSATypeChecking", "false");
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }
}
