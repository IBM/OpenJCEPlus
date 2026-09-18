/*
 * Copyright IBM Corp. 2024, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

abstract public class BaseTestMessageDigest extends BaseTest {

    final byte[] input_1 = {(byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61,
            (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61, (byte) 0x61};

    final byte[] input_2 = {(byte) 0x61, (byte) 0x62, (byte) 0x63};

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

    protected int expectedDigestLength() {
        return -1;
    }

    protected byte[] getSingleBlockInput() {
        return null;
    }

    protected byte[] getExpectedSingleBlockDigest() {
        return null;
    }

    protected byte[] getMultiBlockInput() {
        return null;
    }

    protected byte[] getExpectedMultiBlockDigest() {
        return null;
    }

    protected byte[] getResetFirstInput() {
        return null;
    }

    protected byte[] getResetSecondInput() {
        return null;
    }

    protected byte[] getExpectedResetDigest() {
        return null;
    }

    @Test
    public void testUpdateCloneSameUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        md.update(input_1);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_2);

        assertArrayEquals(digest2, digest1, "Digest of original did not match clone's digest");
    }

    @Test
    public void testUpdateCloneDifferentUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        md.update(input_1);

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_3);

        assertFalse(Arrays.equals(digest1, digest2), "Digest of original matches clone's digest when it shouldn't");
    }

    @Test
    public void testCloneSameUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_2);

        assertArrayEquals(digest2, digest1, "Digest of original did not match clone's digest");
    }

    @Test
    public void testCloneDifferentUpdate() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());

        MessageDigest mdCopy = (MessageDigest) md.clone();

        byte[] digest1 = md.digest(input_2);
        byte[] digest2 = mdCopy.digest(input_3);

        assertFalse(Arrays.equals(digest1, digest2), "Digest of original matches clone's digest when it shouldn't");
    }

    /**
     * Ensure a ArrayIndexOutOfBoundsException is thrown with negative offset parameter.
     */
    @Test
    public void tesNegativeOffset() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] bytes = new byte[] {1, 1, 1, 1, 1};
        try {
            md.update(bytes, -1, 1);
            fail("Expected exception not thrown.");
        } catch (ArrayIndexOutOfBoundsException e) {
            assertEquals("Range out of bounds for buffer of length 5 using offset: -1, input length: 1", e.getMessage());
        }
    }

    /**
     * Ensure a ArrayIndexOutOfBoundsException is thrown with negative length parameter.
     */
    @Test
    public void testNegativeLength() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] bytes = new byte[] {1, 1, 1, 1, 1};
        try {
            md.update(bytes, 1, -1);
            fail("Expected exception not thrown.");
        } catch (ArrayIndexOutOfBoundsException e) {
            assertEquals("Range out of bounds for buffer of length 5 using offset: 1, input length: -1", e.getMessage());
        }
    }

    /**
     * Ensure a IllegalArgumentException is thrown when using a short buffer.
     */
    @Test
    public void testShortBuffer() throws Exception {
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] bytes = new byte[] {1, 1, 1, 1, 1};
        try {
            md.update(bytes, 1, 5);
            fail("Expected exception not thrown.");
        } catch (IllegalArgumentException e) {
            assertEquals("Input buffer too short", e.getMessage());
        }
    }

    @Test
    public void test_DigestLength() throws Exception {
        assumeTrue(expectedDigestLength() >= 0, "Skipping test: not applicable for this algorithm.");
        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        assertTrue(md.getDigestLength() == expectedDigestLength(), "Unexpected digest length");
    }

    @Test
    public void test_SingleBlock() throws Exception {
        byte[] input = getSingleBlockInput();
        assumeTrue(input != null, "Skipping test: not applicable for this algorithm.");

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input);
        assertTrue(Arrays.equals(digest, getExpectedSingleBlockDigest()), "Digest did not match expected");
    }

    @Test
    public void test_MultiBlock() throws Exception {
        byte[] input = getMultiBlockInput();
        assumeTrue(input != null, "Skipping test: not applicable for this algorithm.");

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        byte[] digest = md.digest(input);
        assertTrue(Arrays.equals(digest, getExpectedMultiBlockDigest()), "Digest did not match expected");
    }

    @Test
    public void test_Reset() throws Exception {
        byte[] first = getResetFirstInput();
        assumeTrue(first != null, "Skipping test: not applicable for this algorithm.");

        MessageDigest md = MessageDigest.getInstance(getAlgorithm(), getProviderName());
        md.update(first);
        md.reset();
        md.update(getResetSecondInput());
        byte[] result = md.digest();
        assertTrue(Arrays.equals(result, getExpectedResetDigest()), "Digest did not match expected");
    }
}
