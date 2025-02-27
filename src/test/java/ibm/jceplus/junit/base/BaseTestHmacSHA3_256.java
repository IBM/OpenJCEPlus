/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHmacSHA3_256 extends BaseTestJunit5 {

    // test vectors fromhttps://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values#aMsgAuth

    private static byte[] NISTKEY_172;
    private static byte[] key_1;
    private static String data1;
    private static byte[] data_1;
    private static byte[] digest_1;
    private static byte[] key_2;
    private static String data2;
    private static byte[] data_2;
    private static byte[] digest_2;
    private static byte[] key_3;
    private static String data3;
    private static byte[] data_3;
    private static byte[] digest_3;

    static {

        NISTKEY_172 = new byte[172];
        for (int i = 0; i < NISTKEY_172.length; i++) {
            NISTKEY_172[i] = (byte) i;
        }
        /*
        t("HmacSHA3-256", STR_NIST1, "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205", Arrays.copyOf(NISTKEY_172, 32)),
        t("HmacSHA3-256", STR_NIST2, "68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa", Arrays.copyOf(NISTKEY_172, 136)),
        t("HmacSHA3-256", STR_NIST3, "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258", Arrays.copyOf(NISTKEY_172, 168)),
        */

        key_1 = Arrays.copyOf(NISTKEY_172, 32);

        data1 = "Sample message for keylen<blocklen";
        data_1 = data1.getBytes(StandardCharsets.UTF_8);

        digest_1 = BaseUtils.hexStringToByteArray(
                "4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205");

        key_2 = Arrays.copyOf(NISTKEY_172, 136);

        data2 = "Sample message for keylen=blocklen";
        data_2 = data2.getBytes(StandardCharsets.UTF_8);

        digest_2 = BaseUtils.hexStringToByteArray(
                "68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa");

        key_3 = Arrays.copyOf(NISTKEY_172, 168);

        data3 = "Sample message for keylen>blocklen";
        data_3 = data3.getBytes(StandardCharsets.UTF_8);

        digest_3 = BaseUtils.hexStringToByteArray(
                "9bcf2c238e235c3ce88404e813bd2f3a97185ac6f238c63d6229a00b07974258");
    }

    @Test
    public void testHmacSHA3_256_key1() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-256");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_256_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacSHA3-256");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_2), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_256_key3() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacSHA3-256");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_3), "Mac digest did not equal expected");
    }

    @Test
    public void test_reset() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-256");
        mac.init(key);
        mac.update(data_1);
        mac.reset();
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void test_reuse() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-256");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");

        mac.update(data_1);
        byte[] digest2 = mac.doFinal();

        assertTrue(Arrays.equals(digest2, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void test_mac_length() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-256", getProviderName());
        int macLength = mac.getMacLength();
        boolean isExpectedValue = (macLength == 32);
        assertTrue(isExpectedValue, "Unexpected mac length");
    }
}

