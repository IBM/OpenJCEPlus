/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.Assume;

/**
 * @test
 * @bug 8043836
 * @summary Test AES encryption with no padding. Expect the original data length
 *          is the same as the encrypted data.
 */
public class BaseTestAESGCMNonExpanding extends BaseTest {

    private static final String ALGORITHM = "AES";
    private static final String[] MODES = {"GCM"};
    private static final String PADDING = "NoPadding";
    protected int specifiedKeySize = 128;

    public BaseTestAESGCMNonExpanding(String providerName) {
        super(providerName);
    }

    public BaseTestAESGCMNonExpanding(String providerName, int keySize) throws Exception {
        super(providerName);
        this.specifiedKeySize = keySize;
        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= keySize);
    }


    public void testNonExpanding() throws Exception {

        for (String mode : MODES) {
            doTest(ALGORITHM, mode, PADDING);
        }
    }


    public void doTest(String algo, String mo, String pad) throws Exception {
        Cipher ci = null;
        SecretKey key = null;
        try {
            // Initialization
            Random rdm = new Random();
            byte[] plainText = new byte[128];
            rdm.nextBytes(plainText);

            ci = Cipher.getInstance(algo + "/" + mo + "/" + pad, providerName);

            KeyGenerator kg = KeyGenerator.getInstance(algo, providerName);
            kg.init(specifiedKeySize);
            key = kg.generateKey();

            // encrypt
            ci.init(Cipher.ENCRYPT_MODE, key);
            byte[] cipherText = new byte[ci.getOutputSize(plainText.length)];
            int offset = ci.update(plainText, 0, plainText.length, cipherText, 0);
            ci.doFinal(cipherText, offset);

            // Comparison
            if (!(plainText.length == cipherText.length)) {
                // The result of encryption in GCM is a combination of an
                // authentication tag and cipher text.
                if (mo.equalsIgnoreCase("GCM")) {
                    GCMParameterSpec spec = ci.getParameters()
                            .getParameterSpec(GCMParameterSpec.class);
                    int cipherTextLength = cipherText.length - spec.getTLen() / 8;
                    if (plainText.length == cipherTextLength) {
                        return;
                    }
                }
                System.out.println("Original length: " + plainText.length);
                System.out.println("Cipher text length: " + cipherText.length);
                throw new RuntimeException("Test failed!");
            }
        } catch (NoSuchAlgorithmException e) {
            //CFB7 and OFB150 are for negative testing
            if (!mo.equalsIgnoreCase("CFB7") && !mo.equalsIgnoreCase("OFB150")) {
                System.out.println("Unexpected NoSuchAlgorithmException with mode: " + mo);
                throw new RuntimeException("Test failed!");
            }
        } catch (NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
                | InvalidParameterSpecException | ShortBufferException | IllegalBlockSizeException
                | BadPaddingException e) {
            System.out.println("Test failed!");
            throw e;
        }
    }
}
