/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import ibm.jceplus.junit.tests.parameters.resolvers.RSAKeySizeListParameterResolver;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.provider.MethodSource;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@ExtendWith(RSAKeySizeListParameterResolver.class)
@MethodSource("ibm.jceplus.junit.tests.TestArguments#keySizesAndProviders")
public class TestRSA extends BaseTestRSA {
    // This class is only used to pass the key size parameter to the BaseTestRSA class.
}
