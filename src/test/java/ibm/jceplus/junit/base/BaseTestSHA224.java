/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public class BaseTestSHA224 extends BaseTest {
    static boolean warmup = false;

    //--------------------------------------------------------------------------
    //
    //

    static final byte[] input_1 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};
    static final byte[] digest_1 = {(byte) 0x23, (byte) 0x09, (byte) 0x7d, (byte) 0x22, (byte) 0x34,
            (byte) 0x05, (byte) 0xd8, (byte) 0x22, (byte) 0x86, (byte) 0x42, (byte) 0xa4,
            (byte) 0x77, (byte) 0xbd, (byte) 0xa2, (byte) 0x55, (byte) 0xb3, (byte) 0x2a,
            (byte) 0xad, (byte) 0xbc, (byte) 0xe4, (byte) 0xbd, (byte) 0xa0, (byte) 0xb3,
            (byte) 0xf7, (byte) 0xe3, (byte) 0x6c, (byte) 0x9d, (byte) 0xa7,};

    static final byte[] input_2 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            .getBytes(StandardCharsets.UTF_8);
    static final byte[] digest_2 = {(byte) 0x75, (byte) 0x38, (byte) 0x8b, (byte) 0x16, (byte) 0x51,
            (byte) 0x27, (byte) 0x76, (byte) 0xcc, (byte) 0x5d, (byte) 0xba, (byte) 0x5d,
            (byte) 0xa1, (byte) 0xfd, (byte) 0x89, (byte) 0x01, (byte) 0x50, (byte) 0xb0,
            (byte) 0xc6, (byte) 0x45, (byte) 0x5c, (byte) 0xb4, (byte) 0xf5, (byte) 0x8b,
            (byte) 0x19, (byte) 0x52, (byte) 0x52, (byte) 0x25, (byte) 0x25,};

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestSHA224(String providerName) {
        super(providerName);
        try {
            if (warmup == false) {
                warmup = true;
                warmup();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA224_1() throws Exception {
        boolean result = checkDigest(input_1, digest_1);
        assertTrue("Digest did not match expected, testSHA224_1:", result);

    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA224_2() throws Exception {
        boolean result = checkDigest(input_2, digest_2);
        assertTrue("Digest did not match expected, testSHA224_2", result);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA224_reset() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-224", providerName);
        md.update(input_1);
        md.reset();
        md.update(input_2);
        byte[] result = md.digest();

        assertTrue("Digest did not match expected", Arrays.equals(result, digest_2));
    }

    //--------------------------------------------------------------------------
    //
    //
    public void testSHA224_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-224", providerName);
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 28);
        assertTrue("Unexpected digest length", isExpectedValue);
    }

    //--------------------------------------------------------------------------
    //
    //
    private boolean checkDigest(byte[] input, byte[] out) {
        boolean result = false;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224", providerName);
            byte[] digest = md.digest(input);

            result = Arrays.equals(digest, out);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;

    }

    //--------------------------------------------------------------------------
    //
    //
    public void warmup() throws Exception {

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-224", providerName);
            for (long i = 0; i < 10000; i++) {
                md.update(input_1);
                md.digest();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

