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

public class BaseTestHmacSHA3_512 extends BaseTestJunit5 {

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
        
        t("HmacSHA3-512", STR_NIST1, "4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196", Arrays.copyOf(NISTKEY_172, 64)),
        t("HmacSHA3-512", STR_NIST2, "544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da", Arrays.copyOf(NISTKEY_172, 72)),
        t("HmacSHA3-512", STR_NIST3, "5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915", Arrays.copyOf(NISTKEY_172, 136)),
        
        */

        key_1 = Arrays.copyOf(NISTKEY_172, 64);

        data1 = "Sample message for keylen<blocklen";
        data_1 = data1.getBytes(StandardCharsets.UTF_8);

        digest_1 = BaseUtils.hexStringToByteArray(
                "4efd629d6c71bf86162658f29943b1c308ce27cdfa6db0d9c3ce81763f9cbce5f7ebe9868031db1a8f8eb7b6b95e5c5e3f657a8996c86a2f6527e307f0213196");

        key_2 = Arrays.copyOf(NISTKEY_172, 72);

        data2 = "Sample message for keylen=blocklen";
        data_2 = data2.getBytes(StandardCharsets.UTF_8);

        digest_2 = BaseUtils.hexStringToByteArray(
                "544e257ea2a3e5ea19a590e6a24b724ce6327757723fe2751b75bf007d80f6b360744bf1b7a88ea585f9765b47911976d3191cf83c039f5ffab0d29cc9d9b6da");

        key_3 = Arrays.copyOf(NISTKEY_172, 136);

        data3 = "Sample message for keylen>blocklen";
        data_3 = data3.getBytes(StandardCharsets.UTF_8);

        digest_3 = BaseUtils.hexStringToByteArray(
                "5f464f5e5b7848e3885e49b2c385f0694985d0e38966242dc4a5fe3fea4b37d46b65ceced5dcf59438dd840bab22269f0ba7febdb9fcf74602a35666b2a32915");
    }

    @Test
    public void testHmacSHA3_512_key1() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-512");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_512_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacSHA3-512");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_2), "Mac digest did not equal expected");
    }

    @Test
    public void testHmacSHA3_512_key3() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacSHA3-512");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_3), "Mac digest did not equal expected");
    }

    @Test
    public void test_reset() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-512");
        mac.init(key);
        mac.update(data_1);
        mac.reset();
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue(Arrays.equals(digest, digest_1), "Mac digest did not equal expected");
    }

    @Test
    public void test_reuse() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA3-512");
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
        Mac mac = Mac.getInstance("HmacSHA3-512", getProviderName());
        int macLength = mac.getMacLength();
        boolean isExpectedValue = (macLength == 64);
        assertTrue(isExpectedValue, "Unexpected mac length");
    }
}

