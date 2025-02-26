/*
 * Copyright IBM Corp. 2023, 2024
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

public class BaseTestSHA256 extends BaseTestMessageDigestClone {

    final byte[] input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] result_1 = {(byte) 0xcd, (byte) 0xc7, (byte) 0x6e, (byte) 0x5c, (byte) 0x99,
            (byte) 0x14, (byte) 0xfb, (byte) 0x92, (byte) 0x81, (byte) 0xa1, (byte) 0xc7,
            (byte) 0xe2, (byte) 0x84, (byte) 0xd7, (byte) 0x3e, (byte) 0x67, (byte) 0xf1,
            (byte) 0x80, (byte) 0x9a, (byte) 0x48, (byte) 0xa4, (byte) 0x97, (byte) 0x20,
            (byte) 0x0e, (byte) 0x04, (byte) 0x6d, (byte) 0x39, (byte) 0xcc, (byte) 0xc7,
            (byte) 0x11, (byte) 0x2c, (byte) 0xd0};

    final byte[] input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    final byte[] result_2 = {(byte) 0xba, (byte) 0x78, (byte) 0x16, (byte) 0xbf, (byte) 0x8f,
            (byte) 0x01, (byte) 0xcf, (byte) 0xea, (byte) 0x41, (byte) 0x41, (byte) 0x40,
            (byte) 0xde, (byte) 0x5d, (byte) 0xae, (byte) 0x22, (byte) 0x23, (byte) 0xb0,
            (byte) 0x03, (byte) 0x61, (byte) 0xa3, (byte) 0x96, (byte) 0x17, (byte) 0x7a,
            (byte) 0x9c, (byte) 0xb4, (byte) 0x10, (byte) 0xff, (byte) 0x61, (byte) 0xf2,
            (byte) 0x00, (byte) 0x15, (byte) 0xad};

    final byte[] input_3 = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x62,
            (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63, (byte) 0x64, (byte) 0x65,
            (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x65,
            (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69, (byte) 0x6a, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6b,
            (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71};

    final byte[] result_3 = {(byte) 0x24, (byte) 0x8d, (byte) 0x6a, (byte) 0x61, (byte) 0xd2,
            (byte) 0x06, (byte) 0x38, (byte) 0xb8, (byte) 0xe5, (byte) 0xc0, (byte) 0x26,
            (byte) 0x93, (byte) 0x0c, (byte) 0x3e, (byte) 0x60, (byte) 0x39, (byte) 0xa3,
            (byte) 0x3c, (byte) 0xe4, (byte) 0x59, (byte) 0x64, (byte) 0xff, (byte) 0x21,
            (byte) 0x67, (byte) 0xf6, (byte) 0xec, (byte) 0xed, (byte) 0xd4, (byte) 0x19,
            (byte) 0xdb, (byte) 0x06, (byte) 0xc1

    };

    @BeforeAll
    public void setUp() {
        setAlgorithm("SHA-256");
    }

    @Test
    public void testSHA256() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        for (int i = 0; i < 100000; i++)
            md.update(input_1);
        byte[] digest = md.digest();

        assertTrue(Arrays.equals(digest, result_1), "Digest did not match expected");
    }

    @Test
    public void testSHA256_SingleBlock() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input_2);

        assertTrue(Arrays.equals(digest, result_2), "Digest did not match expected");
    }

    @Test
    public void testSHA256_reset() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(input_1);
        md.reset();
        md.update(input_2);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, result_2), "Digest did not match expected");
    }

    @Test
    public void testSHA256_MultiBlock() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input_3);

        assertTrue(Arrays.equals(digest, result_3), "Digest did not match expected");
    }

    @Test
    public void testSHA256_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 32);
        assertTrue(isExpectedValue, "Unexpected digest length");
    }
}
