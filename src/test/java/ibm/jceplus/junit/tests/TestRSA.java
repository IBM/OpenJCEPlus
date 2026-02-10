/*
 * Copyright IBM Corp. 2026
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
@MethodSource("ibm.jceplus.junit.tests.TestArguments#rsaKeySizesAndJCEPlusProviders")
public class TestRSA extends BaseTestRSA {
// This class is empty which is used to pass the key size and provider parameters to the BaseTestRSA class.
}
