/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestMD5 extends BaseTestMessageDigestClone {

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

    static byte[] md5result = {(byte) 0xb7, (byte) 0x09, (byte) 0xd8, (byte) 0xdb, (byte) 0x29,
            (byte) 0xfb, (byte) 0x0b, (byte) 0xaa, (byte) 0x2e, (byte) 0x45, (byte) 0xc4,
            (byte) 0x07, (byte) 0x89, (byte) 0xad, (byte) 0x6a, (byte) 0xdb};

    // MD5 test vectors from RFC 1321
    // input = ""
    static final byte[] md5_A = {(byte) 0xd4, (byte) 0x1d, (byte) 0x8c, (byte) 0xd9, (byte) 0x8f,
            (byte) 0x00, (byte) 0xb2, (byte) 0x04, (byte) 0xe9, (byte) 0x80, (byte) 0x09,
            (byte) 0x98, (byte) 0xec, (byte) 0xf8, (byte) 0x42, (byte) 0x7e};

    // input = "a";
    static final byte[] md5_B_input = {(byte) 0x61};

    static final byte[] md5_B = {(byte) 0x0c, (byte) 0xc1, (byte) 0x75, (byte) 0xb9, (byte) 0xc0,
            (byte) 0xf1, (byte) 0xb6, (byte) 0xa8, (byte) 0x31, (byte) 0xc3, (byte) 0x99,
            (byte) 0xe2, (byte) 0x69, (byte) 0x77, (byte) 0x26, (byte) 0x61};

    // input = "abc";
    static final byte[] md5_C_input = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

    static final byte[] md5_C = {(byte) 0x90, (byte) 0x01, (byte) 0x50, (byte) 0x98, (byte) 0x3c,
            (byte) 0xd2, (byte) 0x4f, (byte) 0xb0, (byte) 0xd6, (byte) 0x96, (byte) 0x3f,
            (byte) 0x7d, (byte) 0x28, (byte) 0xe1, (byte) 0x7f, (byte) 0x72};

    // input = "message digest";
    static final byte[] md5_D_input = {(byte) 0x6d, (byte) 0x65, (byte) 0x73, (byte) 0x73,
            (byte) 0x61, (byte) 0x67, (byte) 0x65, (byte) 0x20, (byte) 0x64, (byte) 0x69,
            (byte) 0x67, (byte) 0x65, (byte) 0x73, (byte) 0x74};

    static final byte[] md5_D = {(byte) 0xf9, (byte) 0x6b, (byte) 0x69, (byte) 0x7d, (byte) 0x7c,
            (byte) 0xb7, (byte) 0x93, (byte) 0x8d, (byte) 0x52, (byte) 0x5a, (byte) 0x2f,
            (byte) 0x31, (byte) 0xaa, (byte) 0xf1, (byte) 0x61, (byte) 0xd0};

    // input = "abcdefghijklmnopqrstuvwxyz";
    static final byte[] md5_E_input = {(byte) 0x61, (byte) 0x62, (byte) 0x63, (byte) 0x64,
            (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68, (byte) 0x69, (byte) 0x6a,
            (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e, (byte) 0x6f, (byte) 0x70,
            (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74, (byte) 0x75, (byte) 0x76,
            (byte) 0x77, (byte) 0x78, (byte) 0x79, (byte) 0x7a};

    static final byte[] md5_E = {(byte) 0xc3, (byte) 0xfc, (byte) 0xd3, (byte) 0xd7, (byte) 0x61,
            (byte) 0x92, (byte) 0xe4, (byte) 0x00, (byte) 0x7d, (byte) 0xfb, (byte) 0x49,
            (byte) 0x6c, (byte) 0xca, (byte) 0x67, (byte) 0xe1, (byte) 0x3b};

    // input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static final byte[] md5_F_input = {(byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44,
            (byte) 0x45, (byte) 0x46, (byte) 0x47, (byte) 0x48, (byte) 0x49, (byte) 0x4a,
            (byte) 0x4b, (byte) 0x4c, (byte) 0x4d, (byte) 0x4e, (byte) 0x4f, (byte) 0x50,
            (byte) 0x51, (byte) 0x52, (byte) 0x53, (byte) 0x54, (byte) 0x55, (byte) 0x56,
            (byte) 0x57, (byte) 0x58, (byte) 0x59, (byte) 0x5a, (byte) 0x61, (byte) 0x62,
            (byte) 0x63, (byte) 0x64, (byte) 0x65, (byte) 0x66, (byte) 0x67, (byte) 0x68,
            (byte) 0x69, (byte) 0x6a, (byte) 0x6b, (byte) 0x6c, (byte) 0x6d, (byte) 0x6e,
            (byte) 0x6f, (byte) 0x70, (byte) 0x71, (byte) 0x72, (byte) 0x73, (byte) 0x74,
            (byte) 0x75, (byte) 0x76, (byte) 0x77, (byte) 0x78, (byte) 0x79, (byte) 0x7a,
            (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35,
            (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39};

    static final byte[] md5_F = {(byte) 0xd1, (byte) 0x74, (byte) 0xab, (byte) 0x98, (byte) 0xd2,
            (byte) 0x77, (byte) 0xd9, (byte) 0xf5, (byte) 0xa5, (byte) 0x61, (byte) 0x1c,
            (byte) 0x2c, (byte) 0x9f, (byte) 0x41, (byte) 0x9d, (byte) 0x9f};

    // input =
    // "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
    static final byte[] md5_G_input = {(byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34,
            (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30,
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
            (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30, (byte) 0x31, (byte) 0x32,
            (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38,
            (byte) 0x39, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34,
            (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30,
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
            (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30, (byte) 0x31, (byte) 0x32,
            (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38,
            (byte) 0x39, (byte) 0x30, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34,
            (byte) 0x35, (byte) 0x36, (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30,
            (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x34, (byte) 0x35, (byte) 0x36,
            (byte) 0x37, (byte) 0x38, (byte) 0x39, (byte) 0x30};

    static final byte[] md5_G = {(byte) 0x57, (byte) 0xed, (byte) 0xf4, (byte) 0xa2, (byte) 0x2b,
            (byte) 0xe3, (byte) 0xc9, (byte) 0x55, (byte) 0xac, (byte) 0x49, (byte) 0xda,
            (byte) 0x2e, (byte) 0x21, (byte) 0x07, (byte) 0xb6, (byte) 0x7a};

    @Test
    public void testMD5() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        for (int i = 0; i < each.length; i++)
            md.update(each[i]);
        md.update(array1);
        md.update(array2);
        md.update(array3);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5result));

    }

    @Test
    public void testMD5_A() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_A));

    }

    @Test
    public void testMD5_B() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_B_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_B));

    }

    @Test
    public void testMD5_C() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_C_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_C));

    }

    @Test
    public void testMD5_D() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_D_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_D));

    }

    @Test
    public void testMD5_E() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_E_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_E));

    }

    @Test
    public void testMD5_F() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_F_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_F));

    }

    @Test
    public void testMD5_G() throws Exception {

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(md5_G_input);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, md5_G));

    }

}

