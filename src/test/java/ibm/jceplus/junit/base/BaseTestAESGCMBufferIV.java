/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestAESGCMBufferIV extends BaseTestJunit5 {

    private Cipher cipher;
    private SecretKeySpec keySpec;
    private byte plaintext[];

    @BeforeEach
    public void setUp() throws Exception {
        keySpec = new SecretKeySpec(new byte[16], "AES");
        cipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        plaintext = new byte[51];
    }

    @Test
    public void testAESGCMBufferIV() throws Exception {
        testBufferIV(45, 16);
        testBufferIV(46, 12);
        testBufferIV(47, 16);
        testBufferIV(48, 16);
        testBufferIV(49, 128);
        testBufferIV(50, 128);
    }

    private void testBufferIV(int buffLen, int ivLen) throws Exception {
        GCMParameterSpec iv = new GCMParameterSpec(16, generateRandomIv(ivLen));

        System.out.println("Encrypting --- buffLen: " + buffLen + " ivLen: " + ivLen);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
        byte[] cipherText = cipher.doFinal(plaintext);

        System.out.println("Decrypting --- buffLen: " + buffLen + " ivLen: " + ivLen);
        byte[] out = new byte[buffLen];
        int len = cipherText.length - 1;
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
        byte[] pt = new byte[cipher.getOutputSize(cipherText.length)];
        cipher.update(cipherText, 0, 1);
        try {
            cipher.doFinal(cipherText, 1, len, out, 0);
        } catch (ShortBufferException e) {
            System.out.println("ShortBuffer caught");
        } catch (Exception e) {
            throw e;
        }
        int r = cipher.doFinal(cipherText, 1, len, pt, 0);
        if (r != pt.length) {
            throw new Exception("doFinal() return ( " + r + ") is not the same"
                    + "as getOutputSize returned" + pt.length);
        }
        assertTrue(Arrays.equals(pt, plaintext));
    }

    private static byte[] generateRandomIv(int len) {
        byte[] iv = new byte[len];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
