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
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunJCEInteropProvider")
public class TestHmacSHA1Interop extends BaseTestHmacInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    //"Hi There".getBytes();
    static final byte[] data_1 = {(byte) 0x48, (byte) 0x69, (byte) 0x20, (byte) 0x54, (byte) 0x68,
            (byte) 0x65, (byte) 0x72, (byte) 0x65};

    //"what do ya want for nothing?".getBytes();
    static final byte[] data_2 = {(byte) 0x77, (byte) 0x68, (byte) 0x61, (byte) 0x74, (byte) 0x20,
            (byte) 0x64, (byte) 0x6f, (byte) 0x20, (byte) 0x79, (byte) 0x61, (byte) 0x20,
            (byte) 0x77, (byte) 0x61, (byte) 0x6e, (byte) 0x74, (byte) 0x20, (byte) 0x66,
            (byte) 0x6f, (byte) 0x72, (byte) 0x20, (byte) 0x6e, (byte) 0x6f, (byte) 0x74,
            (byte) 0x68, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x3f};

    static final byte[] data_3 = {(byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd, (byte) 0xdd,
            (byte) 0xdd, (byte) 0xdd, (byte) 0xdd};

    static final byte[] data_4 = {(byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd, (byte) 0xcd,
            (byte) 0xcd, (byte) 0xcd, (byte) 0xcd};

    //"Test With Truncation".getBytes();
    static final byte[] data_5 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x57, (byte) 0x69, (byte) 0x74, (byte) 0x68, (byte) 0x20, (byte) 0x54,
            (byte) 0x72, (byte) 0x75, (byte) 0x6e, (byte) 0x63, (byte) 0x61, (byte) 0x74,
            (byte) 0x69, (byte) 0x6f, (byte) 0x6e};

    //"Test Using Larger Than Block-Size Key - Hash Key First".getBytes();//{0xcd};
    static final byte[] data_6 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x2d, (byte) 0x20, (byte) 0x48,
            (byte) 0x61, (byte) 0x73, (byte) 0x68, (byte) 0x20, (byte) 0x4b, (byte) 0x65,
            (byte) 0x79, (byte) 0x20, (byte) 0x46, (byte) 0x69, (byte) 0x72, (byte) 0x73,
            (byte) 0x74};

    //"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
    static final byte[] data_7 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74, (byte) 0x20,
            (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67, (byte) 0x20,
            (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65, (byte) 0x72,
            (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e, (byte) 0x20,
            (byte) 0x42, (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d,
            (byte) 0x53, (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x4b,
            (byte) 0x65, (byte) 0x79, (byte) 0x20, (byte) 0x61, (byte) 0x6e, (byte) 0x64,
            (byte) 0x20, (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65,
            (byte) 0x72, (byte) 0x20, (byte) 0x54, (byte) 0x68, (byte) 0x61, (byte) 0x6e,
            (byte) 0x20, (byte) 0x4f, (byte) 0x6e, (byte) 0x65, (byte) 0x20, (byte) 0x42,
            (byte) 0x6c, (byte) 0x6f, (byte) 0x63, (byte) 0x6b, (byte) 0x2d, (byte) 0x53,
            (byte) 0x69, (byte) 0x7a, (byte) 0x65, (byte) 0x20, (byte) 0x44, (byte) 0x61,
            (byte) 0x74, (byte) 0x61};

    //"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
    static final byte[] data_7_20 = {(byte) 0x54, (byte) 0x65, (byte) 0x73, (byte) 0x74,
            (byte) 0x20, (byte) 0x55, (byte) 0x73, (byte) 0x69, (byte) 0x6e, (byte) 0x67,
            (byte) 0x20, (byte) 0x4c, (byte) 0x61, (byte) 0x72, (byte) 0x67, (byte) 0x65,
            (byte) 0x72, (byte) 0x20, (byte) 0x54, (byte) 0x68};

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        setAlgorithm("HmacSHA1");
    }

    @Override
    protected Stream<Arguments> testVectors() {
        return Stream.of(
                Arguments.of("test_data1", data_1),
                Arguments.of("test_data2", data_2),
                Arguments.of("test_data3", data_3),
                Arguments.of("test_data4", data_4),
                Arguments.of("test_data5", data_5),
                Arguments.of("test_data6", data_6),
                Arguments.of("test_data7", data_7),
                Arguments.of("test_data7_20", data_7_20)
        );
    }
}

