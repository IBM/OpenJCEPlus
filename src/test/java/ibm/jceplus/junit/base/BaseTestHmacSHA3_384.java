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

public class BaseTestHmacSHA3_384 extends BaseTestJunit5 {

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
        t("HmacSHA3-384", STR_NIST1, "d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42", Arrays.copyOf(NISTKEY_172, 48)),
        t("HmacSHA3-384", STR_NIST2, "a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90", Arrays.copyOf(NISTKEY_172, 104)),
        t("HmacSHA3-384", STR_NIST3, "e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac", Arrays.copyOf(NISTKEY_172, 152)),
        */

        key_1 = Arrays.copyOf(NISTKEY_172, 48);

        data1 = "Sample message for keylen<blocklen";
        data_1 = data1.getBytes(StandardCharsets.UTF_8);

        digest_1 = BaseUtils.hexStringToByteArray(
                "d588a3c51f3f2d906e8298c1199aa8ff6296218127f6b38a90b6afe2c5617725bc99987f79b22a557b6520db710b7f42");

        key_2 = Arrays.copyOf(NISTKEY_172, 104);

        data2 = "Sample message for keylen=blocklen";
        data_2 = data2.getBytes(StandardCharsets.UTF_8);

        digest_2 = BaseUtils.hexStringToByteArray(
                "a27d24b592e8c8cbf6d4ce6fc5bf62d8fc98bf2d486640d9eb8099e24047837f5f3bffbe92dcce90b4ed5b1e7e44fa90");

        key_3 = Arrays.copyOf(NISTKEY_172, 152);

        data3 = "Sample message for keylen>blocklen";
        data_3 = data3.getBytes(StandardCharsets.UTF_8);

        digest_3 = BaseUtils.hexStringToByteArray(
                "e5ae4c739f455279368ebf36d4f5354c95aa184c899d3870e460ebc288ef1f9470053f73f7c6da2a71bcaec38ce7d6ac");
    }

    @Test
    public void testHmacSHA3_384_key1() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-384");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_384_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacSHA3-384");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_2), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_384_key3() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacSHA3-384");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_3), "Mac digest did not equal expected");
    }

    @Test
    public void test_reset() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-384");
        mac.init(key);
        mac.update(data_1);
        mac.reset();
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void test_reuse() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-384");
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
        Mac mac = Mac.getInstance("HmacSHA3-384", getProviderName());
        int macLength = mac.getMacLength();
        boolean isExpectedValue = (macLength == 48);
        assertTrue(isExpectedValue, "Unexpected mac length");
    }
}

