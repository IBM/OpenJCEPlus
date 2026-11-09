/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestOAEPOrderCheck extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @Test
    public void testOAEPOrder() throws Exception {
        // Do not use default fields
        OAEPParameterSpec spec = new OAEPParameterSpec(
                "SHA-384", "MGF1", MGF1ParameterSpec.SHA384,
                new PSource.PSpecified(new byte[10]));
        AlgorithmParameters alg = AlgorithmParameters.getInstance("OAEP", getProviderName());
        alg.init(spec);
        byte[] encoded = alg.getEncoded();

        // Extract the fields inside encoding
        // [0] HashAlgorithm
        byte[] a0 = Arrays.copyOfRange(encoded, 2, encoded[3] + 4);
        // [1] MaskGenAlgorithm + [2] PSourceAlgorithm
        byte[] a12 = Arrays.copyOfRange(encoded, 2 + a0.length, encoded.length);

        // and rearrange [1] and [2] before [0]
        System.arraycopy(a12, 0, encoded, 2, a12.length);
        System.arraycopy(a0, 0, encoded, 2 + a12.length, a0.length);

        AlgorithmParameters alg2 = AlgorithmParameters.getInstance("OAEP", getProviderName());
        try {
            alg2.init(encoded);
            throw new RuntimeException("Should fail");
        } catch (IOException ioe) {
            // expected
            assertEquals("Extra unused bytes", ioe.getMessage());
        }
    }
}
