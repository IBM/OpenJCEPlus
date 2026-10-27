/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    public void testPayload_512() throws Exception {
        byte[] data_512 = new byte[512];
        Random r = new Random(10);
        r.nextBytes(data_512);
        doHmac(data_512, getProviderName(), getInteropProviderName());
        doHmac(data_512, getInteropProviderName(), getProviderName());
    }

    @Test
    public void testPayload_2048() throws Exception {
        byte[] data_2048 = new byte[2048];
        Random r = new Random(10);
        r.nextBytes(data_2048);
        doHmac(data_2048, getProviderName(), getInteropProviderName());
        doHmac(data_2048, getInteropProviderName(), getProviderName());
    }

    @Test
    public void testPayload_8192() throws Exception {
        byte[] data_8192 = new byte[8192];
        Random r = new Random(10);
        r.nextBytes(data_8192);
        doHmac(data_8192, getProviderName(), getInteropProviderName());
        doHmac(data_8192, getInteropProviderName(), getProviderName());
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

        assertTrue(Arrays.equals(digest, digest2), "Mac digest did not equal expected");
    }
}
