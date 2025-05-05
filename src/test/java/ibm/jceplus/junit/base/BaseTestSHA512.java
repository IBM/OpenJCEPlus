/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestSHA512 extends BaseTestMessageDigest {

    final byte[] input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] result_1 = {(byte) 0xe7, (byte) 0x18, (byte) 0x48, (byte) 0x3d, (byte) 0x0c,
            (byte) 0xe7, (byte) 0x69, (byte) 0x64, (byte) 0x4e, (byte) 0x2e, (byte) 0x42,
            (byte) 0xc7, (byte) 0xbc, (byte) 0x15, (byte) 0xb4, (byte) 0x63, (byte) 0x8e,
            (byte) 0x1f, (byte) 0x98, (byte) 0xb1, (byte) 0x3b, (byte) 0x20, (byte) 0x44,
            (byte) 0x28, (byte) 0x56, (byte) 0x32, (byte) 0xa8, (byte) 0x03, (byte) 0xaf,
            (byte) 0xa9, (byte) 0x73, (byte) 0xeb, (byte) 0xde, (byte) 0x0f, (byte) 0xf2,
            (byte) 0x44, (byte) 0x87, (byte) 0x7e, (byte) 0xa6, (byte) 0x0a, (byte) 0x4c,
            (byte) 0xb0, (byte) 0x43, (byte) 0x2c, (byte) 0xe5, (byte) 0x77, (byte) 0xc3,
            (byte) 0x1b, (byte) 0xeb, (byte) 0x00, (byte) 0x9c, (byte) 0x5c, (byte) 0x2c,
            (byte) 0x49, (byte) 0xaa, (byte) 0x2e, (byte) 0x4e, (byte) 0xad, (byte) 0xb2,
            (byte) 0x17, (byte) 0xad, (byte) 0x8c, (byte) 0xc0, (byte) 0x9b};

    final byte[] input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] result_2 = {(byte) 0xdd, (byte) 0xaf, (byte) 0x35, (byte) 0xa1, (byte) 0x93,
            (byte) 0x61, (byte) 0x7a, (byte) 0xba, (byte) 0xcc, (byte) 0x41, (byte) 0x73,
            (byte) 0x49, (byte) 0xae, (byte) 0x20, (byte) 0x41, (byte) 0x31, (byte) 0x12,
            (byte) 0xe6, (byte) 0xfa, (byte) 0x4e, (byte) 0x89, (byte) 0xa9, (byte) 0x7e,
            (byte) 0xa2, (byte) 0x0a, (byte) 0x9e, (byte) 0xee, (byte) 0xe6, (byte) 0x4b,
            (byte) 0x55, (byte) 0xd3, (byte) 0x9a, (byte) 0x21, (byte) 0x92, (byte) 0x99,
            (byte) 0x2a, (byte) 0x27, (byte) 0x4f, (byte) 0xc1, (byte) 0xa8, (byte) 0x36,
            (byte) 0xba, (byte) 0x3c, (byte) 0x23, (byte) 0xa3, (byte) 0xfe, (byte) 0xeb,
            (byte) 0xbd, (byte) 0x45, (byte) 0x4d, (byte) 0x44, (byte) 0x23, (byte) 0x64,
            (byte) 0x3c, (byte) 0xe8, (byte) 0x0e, (byte) 0x2a, (byte) 0x9a, (byte) 0xc9,
            (byte) 0x4f, (byte) 0xa5, (byte) 0x4c, (byte) 0xa4, (byte) 0x9f};

    final byte[] input_3 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x62, (byte) 0x63, (byte) 0x64,
            (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x63,
            (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69,
            (byte) 0x6a, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x65, (byte) 0x66, (byte) 0x67,
            (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x66,
            (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x68, (byte) 0x69, (byte) 0x6a,
            (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x69,
            (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f,
            (byte) 0x70, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d,
            (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x6c,
            (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72,
            (byte) 0x73, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71,
            (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x6e, (byte) 0x6f, (byte) 0x70,
            (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75};

    final byte[] result_3 = {(byte) 0x8e, (byte) 0x95, (byte) 0x9b, (byte) 0x75, (byte) 0xda,
            (byte) 0xe3, (byte) 0x13, (byte) 0xda, (byte) 0x8c, (byte) 0xf4, (byte) 0xf7,
            (byte) 0x28, (byte) 0x14, (byte) 0xfc, (byte) 0x14, (byte) 0x3f, (byte) 0x8f,
            (byte) 0x77, (byte) 0x79, (byte) 0xc6, (byte) 0xeb, (byte) 0x9f, (byte) 0x7f,
            (byte) 0xa1, (byte) 0x72, (byte) 0x99, (byte) 0xae, (byte) 0xad, (byte) 0xb6,
            (byte) 0x88, (byte) 0x90, (byte) 0x18, (byte) 0x50, (byte) 0x1d, (byte) 0x28,
            (byte) 0x9e, (byte) 0x49, (byte) 0x00, (byte) 0xf7, (byte) 0xe4, (byte) 0x33,
            (byte) 0x1b, (byte) 0x99, (byte) 0xde, (byte) 0xc4, (byte) 0xb5, (byte) 0x43,
            (byte) 0x3a, (byte) 0xc7, (byte) 0xd3, (byte) 0x29, (byte) 0xee, (byte) 0xb6,
            (byte) 0xdd, (byte) 0x26, (byte) 0x54, (byte) 0x5e, (byte) 0x96, (byte) 0xe5,
            (byte) 0x5b, (byte) 0x87, (byte) 0x4b, (byte) 0xe9, (byte) 0x09};

    @BeforeAll
    public void setUp() {
        setAlgorithm("SHA-512");
    }

    @Test
    public void testSHA512() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        for (int i = 0; i < 100000; i++)
            md.update(input_1);
        byte[] digest = md.digest();

        assertTrue(Arrays.equals(digest, result_1), "Digest did not match expected");

    }

    @Test
    public void testSHA_reset() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(input_1);
        md.reset();
        md.update(input_2);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, result_2), "Digest did not match expected");

    }

    @Test
    public void testSHA512_SingleBlock() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input_2);

        assertTrue(Arrays.equals(digest, result_2), "Digest did not match expected");

    }

    @Test
    public void testSHA512_MultiBlock() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input_3);

        assertTrue(Arrays.equals(digest, result_3), "Digest did not match expected");

    }

    @Test
    public void testSHA512_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 64);
        assertTrue(isExpectedValue, "Unexpected digest length");
    }
}
