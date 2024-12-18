/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.util.Arrays;
import java.util.Random;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestHmacSHA384Interop extends BaseTestJunit5Interop {
    // test vectors from http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/HMAC_SHA384.pdf
    static final byte[] key_1 = BaseUtils.hexStringToByteArray(
            "0001020304050607" + "08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
                    + "202122232425262728292A2B2C2D2E2F3031323334353637"
                    + "38393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
                    + "505152535455565758595A5B5C5D5E5F6061626364656667"
                    + "68696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F");

    static final String data1 = "Sample message for keylen=blocklen";
    static final byte[] data_1 = data1.getBytes();

    static final byte[] digest_1 = BaseUtils
            .hexStringToByteArray("63C5DAA5E651847CA897C95814AB830BEDEDC7D25E83EEF9"
                    + "195CD45857A37F448947858F5AF50CC2B1B730DDF29671A9");

    static final byte[] key_2 = BaseUtils
            .hexStringToByteArray("000102030405060708090A0B0C0D0E0F1011121314151617"
                    + "18191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F");

    static final String data2 = "Sample message for keylen<blocklen";
    static final byte[] data_2 = data2.getBytes();

    static final byte[] digest_2 = BaseUtils
            .hexStringToByteArray("6EB242BDBB582CA17BEBFA481B1E23211464D2B7F8C20B9F"
                    + "F2201637B93646AF5AE9AC316E98DB45D9CAE773675EEED0");

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
    static final byte[] data_3 = data3.getBytes();

    static final byte[] digest_3 = BaseUtils
            .hexStringToByteArray("5B664436DF69B0CA22551231A3F0A3D5B4F97991713CFA84"
                    + "BFF4D0792EFF96C27DCCBBB6F79B65D548B40E8564CEF594");

    static final byte[] key_4 = BaseUtils
            .hexStringToByteArray("00" + "0102030405060708090A0B0C0D0E0F101112131415161718"
                    + "191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30");

    static final String data4 = "Sample message for keylen<blocklen, with truncated tag";
    static final byte[] data_4 = data4.getBytes();

    static final byte[] digest_4 = BaseUtils
            .hexStringToByteArray("C48130D3DF703DD7CDAA56800DFBD2BA2458320E6E1F98FE");

    @Test
    public void test_data1() throws Exception {
        doHmac(data_1, getProviderName(), getInteropProviderName());
        doHmac(data_1, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data2() throws Exception {
        doHmac(data_2, getProviderName(), getInteropProviderName());
        doHmac(data_2, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data3() throws Exception {
        doHmac(data_3, getProviderName(), getInteropProviderName());
        doHmac(data_3, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_data4() throws Exception {
        doHmac(data_4, getProviderName(), getInteropProviderName());
        doHmac(data_4, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_512() throws Exception {
        byte[] data_512 = new byte[512];
        Random r = new Random(10);
        r.nextBytes(data_512);
        doHmac(data_512, getProviderName(), getInteropProviderName());
        doHmac(data_512, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_2048() throws Exception {
        byte[] data_2048 = new byte[2048];
        Random r = new Random(10);
        r.nextBytes(data_2048);
        doHmac(data_2048, getProviderName(), getInteropProviderName());
        doHmac(data_2048, getInteropProviderName(), getProviderName());
    }

    @Test
    public void test_payload_8192() throws Exception {
        byte[] data_8192 = new byte[8192];
        Random r = new Random(10);
        r.nextBytes(data_8192);
        doHmac(data_8192, getProviderName(), getInteropProviderName());
        doHmac(data_8192, getInteropProviderName(), getProviderName());
    }


    protected void doHmac(byte[] data, String provider, String interopProvider) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA384", provider);
        SecretKey key = keyGen.generateKey();

        Mac mac = Mac.getInstance("HmacSHA384", provider);
        mac.init(key);
        mac.update(data);
        byte[] digest = mac.doFinal();

        Mac mac2 = Mac.getInstance("HmacSHA384", interopProvider);
        mac2.init(key);
        mac2.update(data);
        byte[] digest2 = mac2.doFinal();

        assertTrue(Arrays.equals(digest, digest2), "Mac digest did not equal expected");
    }
}

