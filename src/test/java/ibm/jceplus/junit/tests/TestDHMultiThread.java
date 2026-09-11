/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.provider.MethodSource;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestDHMultiThread extends BaseTestDH {

    @Override
    @BeforeEach
    public void setUp() throws Exception {
        super.setUp();
        setMulti(true);
    }
}
