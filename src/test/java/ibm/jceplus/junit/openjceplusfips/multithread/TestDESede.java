/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips.multithread;

import ibm.jceplus.junit.base.BaseTestDESede;
import ibm.jceplus.junit.openjceplusfips.Utils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestDESede extends BaseTestDESede {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    /**
     * 
     * This method is to check whether a mode is valid for the cipher
     * but not supported by a given provider.
    */
    @Override
    public boolean isModeValidButUnsupported(String mode) {
        if (mode.equalsIgnoreCase("CFB") || mode.equalsIgnoreCase("CFB64")
                || mode.equalsIgnoreCase("OFB")) {
            return true;
        }

        return super.isModeValidButUnsupported(mode);
    }
}
