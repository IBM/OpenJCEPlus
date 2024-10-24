/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.junit.Assert.assertTrue;

public class BaseTestHmacSHA512 extends BaseTestJunit5 {
    // test vectors from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA512.pdf
    static final byte[] key_1 = BaseUtils.hexStringToByteArray(
            "0001020304050607" + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                    + "202122232425262728292A2B2C2D2E2F3031323334353637"
                    + "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
                    + "505152535455565758595A5B5C5D5E5F6061626364656667"
                    + "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

    static final String data1 = "Sample message for keylen=blocklen";
    static final byte[] data_1 = data1.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_1 = BaseUtils.hexStringToByteArray(
            "FC25E240658CA785B7A811A8D3F7B4CA" + "48CFA26A8A366BF2CD1F836B05FCB024BD36853081811D6C"
                    + "EA4216EBAD79DA1CFCB95EA4586B8A0CE356596A55FB1347");

    static final byte[] key_2 = BaseUtils.hexStringToByteArray(
            "000102030405060708090A0B0C0D0E0F" + "101112131415161718191A1B1C1D1E1F2021222324252627"
                    + "28292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F");

    static final String data2 = "Sample message for keylen<blocklen";
    static final byte[] data_2 = data2.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_2 = BaseUtils.hexStringToByteArray(
            "FD44C18BDA0BB0A6CE0E82B031BF2818" + "F6539BD56EC00BDC10A8A2D730B3634DE2545D639B0F2CF7"
                    + "10D0692C72A1896F1F211C2B922D1A96C392E07E7EA9FEDC");

    static final byte[] key_3 = BaseUtils.hexStringToByteArray(
            "0001020304050607" + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                    + "202122232425262728292A2B2C2D2E2F3031323334353637"
                    + "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
                    + "505152535455565758595A5B5C5D5E5F6061626364656667"
                    + "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
                    + "808182838485868788898A8B8C8D8E8F9091929394959697"
                    + "98999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
                    + "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7");

    static final String data3 = "Sample message for keylen=blocklen";
    static final byte[] data_3 = data3.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_3 = BaseUtils.hexStringToByteArray(
            "D93EC8D2DE1AD2A9957CB9B83F14E76A" + "D6B5E0CCE285079A127D3B14BCCB7AA7286D4AC0D4CE6421"
                    + "5F2BC9E6870B33D97438BE4AAA20CDA5C5A912B48B8E27F3");

    static final byte[] key_4 = BaseUtils
            .hexStringToByteArray("00" + "0102030405060708090A0B0C0D0E0F101112131415161718"
                    + "191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30");

    static final String data4 = "Sample message for keylen<blocklen, with truncated tag";
    static final byte[] data_4 = data4.getBytes(StandardCharsets.UTF_8);

    static final byte[] digest_4 = BaseUtils.hexStringToByteArray(
            "00F3E9A77BB0F06D" + "E15F160603E42B5028758808596664C03E1AB8FB2B076778");

    @Test
    public void testHmacSHA512_key1() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA512");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_1));
    }

    @Test
    public void testHmacSHA512_key2() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_2, "HmacSHA512");
        mac.init(key);
        mac.update(data_2);
        byte[] digest = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_2));
    }

    @Test
    public void testHmacSHA512_key3() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_3, "HmacSHA512");
        mac.init(key);
        mac.update(data_3);
        byte[] digest = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_3));
    }

    @Test
    public void testHmacSHA512_key4() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_4, "HmacSHA512");
        mac.init(key);
        mac.update(data_4);
        byte[] digest = mac.doFinal();

        int taglen = 32;
        byte[] truncatedDigest = new byte[taglen];
        System.arraycopy(digest, 0, truncatedDigest, 0, taglen);

        assertTrue("Mac digest did not equal expected", Arrays.equals(truncatedDigest, digest_4));
    }

    @Test
    public void test_reset() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA512");
        mac.init(key);
        mac.update(data_1);
        mac.reset();
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_1));
    }

    @Test
    public void test_reuse() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        SecretKeySpec key = new SecretKeySpec(key_1, "HmacSHA512");
        mac.init(key);
        mac.update(data_1);
        byte[] digest = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest, digest_1));

        mac.update(data_1);
        byte[] digest2 = mac.doFinal();

        assertTrue("Mac digest did not equal expected", Arrays.equals(digest2, digest_1));
    }

    @Test
    public void test_mac_length() throws Exception {
        Mac mac = Mac.getInstance("HmacSHA512", getProviderName());
        int macLength = mac.getMacLength();
        boolean isExpectedValue = (macLength == 64);
        assertTrue("Unexpected mac length", isExpectedValue);
    }
}

