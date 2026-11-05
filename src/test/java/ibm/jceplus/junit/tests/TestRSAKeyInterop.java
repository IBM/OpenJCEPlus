/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.provider.MethodSource;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunRsaSignAndSunJCEInteropProviders")
public class TestRSAKeyInterop extends BaseTestRSAKeyInterop {
    // This class is only used to pass the provider parameters to the BaseTestRSAKeyInterop class.
}
