/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.nio.charset.StandardCharsets;
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
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestHmacSHA224 extends BaseTestHmac {

    @Parameter(0)
    TestProvider provider;

    // test vectors from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA224.pdf
    static final byte[] key_1 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
            (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10,
            (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16,
            (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c,
            (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
            (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28,
            (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c, (byte) 0x2d, (byte) 0x2e,
            (byte) 0x2f, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34,
            (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x3a,
            (byte) 0x3b, (byte) 0x3c, (byte) 0x3d, (byte) 0x3e, (byte) 0x3f};

    static final String data1 = "Sample message for keylen=blocklen";
    static final byte[] data_1 = data1.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_1 = {(byte) 0xc7, (byte) 0x40, (byte) 0x5e, (byte) 0x3a, (byte) 0xe0,
            (byte) 0x58, (byte) 0xe8, (byte) 0xcd, (byte) 0x30, (byte) 0xb0, (byte) 0x8b,
            (byte) 0x41, (byte) 0x40, (byte) 0x24, (byte) 0x85, (byte) 0x81, (byte) 0xed,
            (byte) 0x17, (byte) 0x4c, (byte) 0xb3, (byte) 0x4e, (byte) 0x12, (byte) 0x24,
            (byte) 0xbc, (byte) 0xc1, (byte) 0xef, (byte) 0xc8, (byte) 0x1b, };

    static final byte[] key_2 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
            (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10,
            (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16,
            (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, };

    static final String data2 = "Sample message for keylen<blocklen";
    static final byte[] data_2 = data2.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_2 = {(byte) 0xe3, (byte) 0xd2, (byte) 0x49, (byte) 0xa8, (byte) 0xcf,
            (byte) 0xb6, (byte) 0x7e, (byte) 0xf8, (byte) 0xb7, (byte) 0xa1, (byte) 0x69,
            (byte) 0xe9, (byte) 0xa0, (byte) 0xa5, (byte) 0x99, (byte) 0x71, (byte) 0x4a,
            (byte) 0x2c, (byte) 0xec, (byte) 0xba, (byte) 0x65, (byte) 0x99, (byte) 0x9a,
            (byte) 0x51, (byte) 0xbe, (byte) 0xb8, (byte) 0xfb, (byte) 0xbe, };

    static final byte[] key_3 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
            (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10,
            (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16,
            (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c,
            (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
            (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28,
            (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c, (byte) 0x2d, (byte) 0x2e,
            (byte) 0x2f, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34,
            (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x3a,
            (byte) 0x3b, (byte) 0x3c, (byte) 0x3d, (byte) 0x3e, (byte) 0x3f, (byte) 0x40,
            (byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46,
            (byte) 0x47, (byte) 0x48, (byte) 0x49, (byte) 0x4a, (byte) 0x4b, (byte) 0x4c,
            (byte) 0x4d, (byte) 0x4e, (byte) 0x4f, (byte) 0x50, (byte) 0x51, (byte) 0x52,
            (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x56, (byte) 0x57, (byte) 0x58,
            (byte) 0x59, (byte) 0x5a, (byte) 0x5b, (byte) 0x5c, (byte) 0x5d, (byte) 0x5e,
            (byte) 0x5f, (byte) 0x60, (byte) 0x61, (byte) 0x62, (byte) 0x63, };

    static final byte[] data_3 = data1.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_3 = {(byte) 0x91, (byte) 0xc5, (byte) 0x25, (byte) 0x09, (byte) 0xe5,
            (byte) 0xaf, (byte) 0x85, (byte) 0x31, (byte) 0x60, (byte) 0x1a, (byte) 0xe6,
            (byte) 0x23, (byte) 0x00, (byte) 0x99, (byte) 0xd9, (byte) 0x0b, (byte) 0xef,
            (byte) 0x88, (byte) 0xaa, (byte) 0xef, (byte) 0xb9, (byte) 0x61, (byte) 0xf4,
            (byte) 0x08, (byte) 0x0a, (byte) 0xbc, (byte) 0x01, (byte) 0x4d, };

    static final byte[] key_4 = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
            (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08, (byte) 0x09, (byte) 0x0a,
            (byte) 0x0b, (byte) 0x0c, (byte) 0x0d, (byte) 0x0e, (byte) 0x0f, (byte) 0x10,
            (byte) 0x11, (byte) 0x12, (byte) 0x13, (byte) 0x14, (byte) 0x15, (byte) 0x16,
            (byte) 0x17, (byte) 0x18, (byte) 0x19, (byte) 0x1a, (byte) 0x1b, (byte) 0x1c,
            (byte) 0x1d, (byte) 0x1e, (byte) 0x1f, (byte) 0x20, (byte) 0x21, (byte) 0x22,
            (byte) 0x23, (byte) 0x24, (byte) 0x25, (byte) 0x26, (byte) 0x27, (byte) 0x28,
            (byte) 0x29, (byte) 0x2a, (byte) 0x2b, (byte) 0x2c, (byte) 0x2d, (byte) 0x2e,
            (byte) 0x2f, (byte) 0x30, };

    static final String data4 = "Sample message for keylen<blocklen, with truncated tag";
    static final byte[] data_4 = data4.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_4 = {(byte) 0xd5, (byte) 0x22, (byte) 0xf1, (byte) 0xdf, (byte) 0x59,
            (byte) 0x6c, (byte) 0xa4, (byte) 0xb4, (byte) 0xb1, (byte) 0xc2, (byte) 0x3d,
            (byte) 0x27, (byte) 0xbd, (byte) 0xe0, (byte) 0x67, (byte) 0xd6, };

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    @Override
    protected String algorithmName() {
        return "HmacSHA224";
    }

    @Override
    protected int expectedMacLength() {
        return 28;
    }

    @Override
    protected Stream<Arguments> testVectors() {
        return Stream.of(
                Arguments.of("testHmacSHA224_key1", key_1, data_1, digest_1, -1),
                Arguments.of("testHmacSHA224_key2", key_2, data_2, digest_2, -1),
                Arguments.of("testHmacSHA224_key3", key_3, data_3, digest_3, -1),
                Arguments.of("testHmacSHA224_key4", key_4, data_4, digest_4, 16));
    }

    @Override
    protected Arguments reuseVector() {
        return Arguments.of("test_reuse", key_3, data_3, digest_3);
    }

    @Override
    protected Arguments resetVector() {
        return Arguments.of("test_reset", key_3, data_3, digest_3);
    }
}

