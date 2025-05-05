/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestSHA224 extends BaseTestMessageDigest {
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

    @BeforeAll
    public void setUp() {
        setAlgorithm("SHA-224");
    }

    @Test
    public void testSHA224_1() throws Exception {
        boolean result = checkDigest(input_1, digest_1);
        assertTrue(result, "Digest did not match expected, testSHA224_1:");

    }

    @Test
    public void testSHA224_2() throws Exception {
        boolean result = checkDigest(input_2, digest_2);
        assertTrue(result, "Digest did not match expected, testSHA224_2");
    }

    @Test
    public void testSHA224_reset() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(input_1);
        md.reset();
        md.update(input_2);
        byte[] result = md.digest();

        assertTrue(Arrays.equals(result, digest_2), "Digest did not match expected");
    }

    @Test
    public void testSHA224_digestLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        int digestLength = md.getDigestLength();
        boolean isExpectedValue = (digestLength == 28);
        assertTrue(isExpectedValue, "Unexpected digest length");
    }


    private boolean checkDigest(byte[] input, byte[] out) {
        boolean result = false;
        try {
            MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
            byte[] digest = md.digest(input);

            result = Arrays.equals(digest, out);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;

    }
}

