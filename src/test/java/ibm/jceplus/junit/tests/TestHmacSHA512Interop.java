/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunJCEInteropProvider")
public class TestHmacSHA512Interop extends BaseTestHmacInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    static final String data1 = "Sample message for keylen=blocklen";
    static final byte[] data_1 = data1.getBytes();

    static final String data2 = "Sample message for keylen<blocklen";
    static final byte[] data_2 = data2.getBytes();

    static final String data3 = "Sample message for keylen=blocklen";
    static final byte[] data_3 = data3.getBytes();

    static final String data4 = "Sample message for keylen<blocklen, with truncated tag";
    static final byte[] data_4 = data4.getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        setAlgorithm("HmacSHA512");
    }

    @Override
    protected Stream<Arguments> testVectors() {
        return Stream.of(
                Arguments.of("test_data1", data_1),
                Arguments.of("test_data2", data_2),
                Arguments.of("test_data3", data_3),
                Arguments.of("test_data4", data_4)
        );
    }
}

