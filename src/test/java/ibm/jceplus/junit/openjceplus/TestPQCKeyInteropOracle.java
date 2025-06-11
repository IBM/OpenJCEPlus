/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestPQCKeyInterop;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.condition.OS;

@TestInstance(Lifecycle.PER_CLASS)
@DisabledOnOs(value = OS.MAC, architectures = "x86_64")
@EnabledForJreRange(min = JRE.JAVA_24)
public class TestPQCKeyInteropOracle extends BaseTestPQCKeyInterop {

    @BeforeAll
    public void beforeAll() throws Exception {
        Utils.loadProviderTestSuite();
        Utils.loadProviderBC();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
        setInteropProviderName(Utils.PROVIDER_SunJCE);
        setInteropProviderName2(Utils.PROVIDER_SUN);
    }
}
