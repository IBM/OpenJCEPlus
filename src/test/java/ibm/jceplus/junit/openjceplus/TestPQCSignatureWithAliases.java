/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.openjceplus;

import ibm.jceplus.junit.base.BaseTestPQCSignatureWithAliases;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
<<<<<<< HEAD

@TestInstance(Lifecycle.PER_CLASS)
=======
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import org.junit.jupiter.api.condition.OS;

@TestInstance(Lifecycle.PER_CLASS)
@DisabledOnOs(value = OS.MAC, architectures = "x86_64")
@EnabledForJreRange(min = JRE.JAVA_17)
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
public class TestPQCSignatureWithAliases extends BaseTestPQCSignatureWithAliases {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }
}
