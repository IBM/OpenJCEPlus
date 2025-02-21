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

public class BaseTestHmacSHA3_224 extends BaseTestJunit5 {

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
        t("HmacSHA3-224", STR_NIST1, "332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04", Arrays.copyOf(NISTKEY_172, 28)),
        t("HmacSHA3-224", STR_NIST2, "d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7", Arrays.copyOf(NISTKEY_172, 144)),
        t("HmacSHA3-224", STR_NIST3, "078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59", NISTKEY_172),
        */

        key_1 = Arrays.copyOf(NISTKEY_172, 28);

        data1 = "Sample message for keylen<blocklen";
        data_1 = data1.getBytes(StandardCharsets.UTF_8);

        digest_1 = BaseUtils
                .hexStringToByteArray("332cfd59347fdb8e576e77260be4aba2d6dc53117b3bfb52c6d18c04");

        key_2 = Arrays.copyOf(NISTKEY_172, 144);

        data2 = "Sample message for keylen=blocklen";
        data_2 = data2.getBytes(StandardCharsets.UTF_8);

        digest_2 = BaseUtils
                .hexStringToByteArray("d8b733bcf66c644a12323d564e24dcf3fc75f231f3b67968359100c7");

        key_3 = NISTKEY_172.clone();

        data3 = "Sample message for keylen>blocklen";
        data_3 = data3.getBytes(StandardCharsets.UTF_8);

        digest_3 = BaseUtils
                .hexStringToByteArray("078695eecc227c636ad31d063a15dd05a7e819a66ec6d8de1e193e59");
    }

    @Test
    public void testHmacSHA3_224_key1() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-224");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_224_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacSHA3-224");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_2), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_224_key3() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacSHA3-224");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_3), "Mac digest did not equal expected");
    }

    @Test
    public void test_reset() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-224");
        mac.init(key);
        mac.update(data_1);
        mac.reset();
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void test_reuse() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-224");
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
        Mac mac = Mac.getInstance("HmacSHA3-224", getProviderName());
        int macLength = mac.getMacLength();
        boolean isExpectedValue = (macLength == 28);
        assertTrue(isExpectedValue, "Unexpected mac length");
    }
}

