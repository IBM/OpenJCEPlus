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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public abstract class BaseTestHmac extends BaseTest {

    /**
     * Returns the expected length of the MAC output for the HMAC algorithm being tested.
     *
     * @return the expected MAC output length
     */
    protected abstract int expectedMacLength();

    /**
     * Returns a stream of test vectors for the HMAC algorithm being tested
     *
     * @return a stream of test vectors
     */
    protected abstract Stream<Arguments> testVectors();

    /**
     * Returns a test vector for testing the reuse of the Mac instance
     *
     * @return a test vector for testing Mac instance reuse
     */
    protected abstract Arguments reuseVector();

    /**
     * Returns a test vector for testing the reset functionality of the Mac instance.
     *
     * @return a test vector for testing the reset functionality
     */
    protected abstract Arguments resetVector();

    @ParameterizedTest(name = "{0}")
    @MethodSource("testVectors")
    public void testHmacVector(String label, byte[] key, byte[] data,
            byte[] expected, int truncateTo) throws Exception {
        Mac mac = Mac.getInstance(getAlgorithm(), getProviderName());
        mac.init(new SecretKeySpec(key, getAlgorithm()));
        mac.update(data);
        byte[] digest = mac.doFinal();
        if (truncateTo > 0) {
            byte[] truncatedDigest = new byte[truncateTo];
            System.arraycopy(digest, 0, truncatedDigest, 0, truncateTo);
            assertArrayEquals(expected, truncatedDigest, "Mac digest did not equal expected");
        } else {
            assertArrayEquals(expected, digest, "Mac digest did not equal expected");
        }
    }

    @Test
    public void testReuse() throws Exception {
        Arguments args = reuseVector();
        byte[] key = (byte[]) args.get()[1];
        byte[] data = (byte[]) args.get()[2];
        byte[] expectedDigest = (byte[]) args.get()[3];

        Mac mac = Mac.getInstance(getAlgorithm(), getProviderName());
        SecretKeySpec keySpec = new SecretKeySpec(key, getAlgorithm());
        mac.init(keySpec);
        mac.update(data);
        assertArrayEquals(expectedDigest, mac.doFinal(), "Mac digest did not equal expected");
        mac.update(data);
        assertArrayEquals(expectedDigest, mac.doFinal(), "Mac digest did not equal expected");
    }

    @Test
    public void testReset() throws Exception {
        Arguments v   = resetVector();
        byte[] key    = (byte[]) v.get()[1];
        byte[] data   = (byte[]) v.get()[2];
        byte[] expectedDigest = (byte[]) v.get()[3];

        Mac mac = Mac.getInstance(getAlgorithm(), getProviderName());
        SecretKeySpec keysSpec = new SecretKeySpec(key, getAlgorithm());
        mac.init(keysSpec);
        mac.update(data);
        mac.reset();
        mac.update(data);
        assertArrayEquals(expectedDigest, mac.doFinal(), "Mac digest did not equal expected");
    }

    @Test
    public void testMacLength() throws Exception {
        Mac mac = Mac.getInstance(getAlgorithm(), getProviderName());
        assertEquals(expectedMacLength(), mac.getMacLength(), "Unexpected mac length");
    }
}
