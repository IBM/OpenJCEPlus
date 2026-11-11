/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.Random;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public abstract class BaseTestHmacInterop extends BaseTestInterop {

    /**
     * Returns a stream of test vectors for the HMAC algorithm being tested.
     *
     * @return a stream of test vectors
     */
    protected abstract Stream<Arguments> testVectors();

    @ParameterizedTest(name = "{0}")
    @MethodSource("testVectors")
    public void testHmacInterop(String name, byte[] data) throws Exception {
        doHmac(data, getProviderName(), getInteropProviderName());
        doHmac(data, getInteropProviderName(), getProviderName());
    }

    @ParameterizedTest(name = "payload size = {0}")
    @CsvSource({"512", "2048", "8192"})
    public void testPayload(int size) throws Exception {
        byte[] data = new byte[size];
        Random r = new Random(10);
        r.nextBytes(data);
        doHmac(data, getProviderName(), getInteropProviderName());
        doHmac(data, getInteropProviderName(), getProviderName());
    }

    protected void doHmac(byte[] data, String provider, String interopProvider) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(getAlgorithm(), provider);
        SecretKey key = keyGen.generateKey();

        Mac mac = Mac.getInstance(getAlgorithm(), provider);
        mac.init(key);
        mac.update(data);
        byte[] digest = mac.doFinal();

        Mac mac2 = Mac.getInstance(getAlgorithm(), interopProvider);
        mac2.init(key);
        mac2.update(data);
        byte[] digest2 = mac2.doFinal();

        assertArrayEquals(digest, digest2, "Mac digest did not equal expected");
    }
}
