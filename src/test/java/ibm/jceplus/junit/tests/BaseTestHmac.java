/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class BaseTestHmac extends BaseTest {

    // This method should return the name of the specific HMAC algorithm being tested (e.g., "HmacSHA1", "HmacSHA224", etc.).
    protected abstract String algorithmName();

    // This method should return the expected length of the MAC output for the specific HMAC algorithm being tested.
    protected abstract int expectedMacLength();

    // This method should return a stream of test vectors for the specific HMAC algorithm being tested.
    protected abstract Stream<Arguments> testVectors();

    // This method should return a test vector for testing the reuse of the Mac instance.
    protected abstract Arguments reuseVector();

    // This method should return a test vector for testing the reset functionality of the Mac instance.
    protected abstract Arguments resetVector();

    @DisplayName("testHmacVector")
    @ParameterizedTest(name = "{0}")
    @MethodSource("testVectors")
    public void testHmacVector(String label, byte[] key, byte[] data,
            byte[] expected, int truncateTo) throws Exception {
        Mac mac = Mac.getInstance(algorithmName(), getProviderName());
        mac.init(new SecretKeySpec(key, algorithmName()));
        mac.update(data);
        byte[] digest = mac.doFinal();
        if (truncateTo > 0) {
            byte[] truncatedDigest = new byte[truncateTo];
            System.arraycopy(digest, 0, truncatedDigest, 0, truncateTo);
            assertArrayEquals(truncatedDigest, expected, "Mac digest did not equal expected");
        } else {
            assertArrayEquals(digest, expected, "Mac digest did not equal expected");
        }
    }

    @Test
    public void test_reuse() throws Exception {
        Arguments args = reuseVector();
        byte[] key = (byte[]) args.get()[1];
        byte[] data = (byte[]) args.get()[2];
        byte[] expected_digest = (byte[]) args.get()[3];

        Mac mac = Mac.getInstance(algorithmName(), getProviderName());
        SecretKeySpec keySpec = new SecretKeySpec(key, algorithmName());
        mac.init(keySpec);
        mac.update(data);
        assertArrayEquals(mac.doFinal(), expected_digest, "Mac digest did not equal expected");
        mac.update(data);
        assertArrayEquals(mac.doFinal(), expected_digest, "Mac digest did not equal expected");
    }

    @Test
    public void test_reset() throws Exception {
        Arguments v   = resetVector();
        byte[] key    = (byte[]) v.get()[1];
        byte[] data   = (byte[]) v.get()[2];
        byte[] expected_digest = (byte[]) v.get()[3];

        Mac mac = Mac.getInstance(algorithmName(), getProviderName());
        SecretKeySpec keysSpec = new SecretKeySpec(key, algorithmName());
        mac.init(keysSpec);
        mac.update(data);
        mac.reset();
        mac.update(data);
        assertArrayEquals(mac.doFinal(), expected_digest, "Mac digest did not equal expected");
    }

    @Test
    public void test_mac_length() throws Exception {
        Mac mac = Mac.getInstance(algorithmName(), getProviderName());
        assertEquals(expectedMacLength(), mac.getMacLength(), "Unexpected mac length");
    }
}
