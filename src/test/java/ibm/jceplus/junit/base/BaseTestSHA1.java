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

public class BaseTestSHA1 extends BaseTestMessageDigest {

    static byte[] each = {(byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x1, (byte) 0x0, (byte) 0x73,
            (byte) 0x0, (byte) 0x75, (byte) 0x0, (byte) 0x62, (byte) 0x0, (byte) 0x2d, (byte) 0x0,
            (byte) 0x61, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x0,
            (byte) 0x0, (byte) 0x0, (byte) 0x0, (byte) 0x3};

    static byte[] array1 = {(byte) 0xc1, (byte) 0x4a, (byte) 0x67, (byte) 0x79, (byte) 0x64,
            (byte) 0x4c, (byte) 0x4c, (byte) 0x4f, (byte) 0xb1, (byte) 0xdf, (byte) 0x67,
            (byte) 0x9d, (byte) 0x4, (byte) 0x26, (byte) 0x4e, (byte) 0x52};

    static byte[] array2 = {(byte) 0xee, (byte) 0x4e, (byte) 0xea, (byte) 0xa8, (byte) 0xdf,
            (byte) 0x73, (byte) 0x12, (byte) 0xd6, (byte) 0xee, (byte) 0xcd, (byte) 0x10,
            (byte) 0x15, (byte) 0x71, (byte) 0xb5, (byte) 0x6f, (byte) 0x34};

    static byte[] array3 = {(byte) 0xc1, (byte) 0x4a, (byte) 0x67, (byte) 0x79, (byte) 0x64,
            (byte) 0x4c, (byte) 0x4c, (byte) 0x4f, (byte) 0xb1, (byte) 0xdf, (byte) 0x67,
            (byte) 0x9d, (byte) 0x4, (byte) 0x26, (byte) 0x4e, (byte) 0x52};

    static byte[] sharesult = {(byte) 0x87, (byte) 0xe6, (byte) 0x4e, (byte) 0xac, (byte) 0xac,
            (byte) 0xc8, (byte) 0x28, (byte) 0x09, (byte) 0x36, (byte) 0xb2, (byte) 0xe8,
            (byte) 0xc4, (byte) 0xb7, (byte) 0x6e, (byte) 0xf2, (byte) 0x68, (byte) 0x1a,
            (byte) 0xea, (byte) 0x2a, (byte) 0xba};

    // SHA test vectors from FIPS PUB 180-1
    // input = "abc";
    static final byte[] sha_A_input = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    static final byte[] sha_A = {(byte) 0xA9, (byte) 0x99, (byte) 0x3E, (byte) 0x36, (byte) 0x47,
            (byte) 0x06, (byte) 0x81, (byte) 0x6A, (byte) 0xBA, (byte) 0x3E, (byte) 0x25,
            (byte) 0x71, (byte) 0x78, (byte) 0x50, (byte) 0xC2, (byte) 0x6C, (byte) 0x9C,
            (byte) 0xD0, (byte) 0xD8, (byte) 0x9D};

    //"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes();
    static final byte[] sha_B_input = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64,
            (byte) 0x62, (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x63, (byte) 0x64,
            (byte) 0x65, (byte) 0x66, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67,
            (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x66, (byte) 0x67,
            (byte) 0x68, (byte) 0x69, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a,
            (byte) 0x68, (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x69, (byte) 0x6a,
            (byte) 0x6b, (byte) 0x6c, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d,
            (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6c, (byte) 0x6d,
            (byte) 0x6e, (byte) 0x6f, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70,
            (byte) 0x6e, (byte) 0x6f, (byte) 0x70, (byte) 0x71};

    // input = "a";
    static final byte[] sha_B = {(byte) 0x84, (byte) 0x98, (byte) 0x3E, (byte) 0x44, (byte) 0x1C,
            (byte) 0x3B, (byte) 0xD2, (byte) 0x6E, (byte) 0xBA, (byte) 0xAE, (byte) 0x4A,
            (byte) 0xA1, (byte) 0xF9, (byte) 0x51, (byte) 0x29, (byte) 0xE5, (byte) 0xE5,
            (byte) 0x46, (byte) 0x70, (byte) 0xF1};

    static final byte[] sha_C = {(byte) 0x34, (byte) 0xAA, (byte) 0x97, (byte) 0x3C, (byte) 0xD4,
            (byte) 0xC4, (byte) 0xDA, (byte) 0xA4, (byte) 0xF6, (byte) 0x1E, (byte) 0xEB,
            (byte) 0x2B, (byte) 0xDB, (byte) 0xAD, (byte) 0x27, (byte) 0x31, (byte) 0x65,
            (byte) 0x34, (byte) 0x01, (byte) 0x6F};
    @BeforeAll
    public void setUp() {
        setAlgorithm("SHA1");
    }

    @Test
    public void testSHA1() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        for (int i = 0; i < each.length; i++)
            md.update(each[i]);
        md.update(array1);
        md.update(array2);
        md.update(array3);

        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, sharesult), "Digest did not match expected");

    }

    @Test
    public void testSHA1_A() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(sha_A_input);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, sha_A), "Digest did not match expected");

    }

    @Test
    public void testSHA1_B() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(sha_B_input);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, sha_B), "Digest did not match expected");

    }

    @Test
    public void testSHA1_C() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        for (int counter = 0; counter < 1000000; counter++) {
            md.update((byte) 0x61);
        }

        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, sha_C), "Digest did not match expected");

    }

    @Test
    public void testSHA1_reset() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(sha_A_input);
        md.reset();
        md.update(sha_B_input);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, sha_B), "Digest did not match expected");

    }

    @Test
    public void testSHA1_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 20);
        assertTrue(isExpectedValue, "Unexpected digest length");
    }

    @Test
    public void testSHA1_ArrayOutofBoundsException() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] bytes = new byte[] {1, 1, 1, 1, 1};
        try {
            md.update(bytes, -1, 1);
            assertTrue(false, "No expected IndexOutOfBoundsException");
        } catch (IndexOutOfBoundsException e) {
            assertTrue(true, "Expected IndexOutOfBoundsException");
        }

    }
}

