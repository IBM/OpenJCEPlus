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
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Exercises XDH key interoperability between the OCK and OpenSSL backends
 * of the same OpenJCEPlus provider, in both directions.
 *
 * <p>OpenSSL is not available on z/OS; the factory method returns an empty stream there,
 * so no test cases will be generated on that platform.
 */
@Tag(Tags.OPENJCEPLUS_OCK_NAME)
@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOCKAndOpenSSLCrossBackendProviders")
public class TestXDHInteropBackends extends BaseTestXDHInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
    }
}
