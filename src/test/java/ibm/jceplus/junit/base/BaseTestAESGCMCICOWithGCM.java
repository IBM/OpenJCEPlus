/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.Assume;

public class BaseTestAESGCMCICOWithGCM extends BaseTest {
    protected int specifiedKeySize = 128;

    public BaseTestAESGCMCICOWithGCM(String providerName) {
        super(providerName);
    }

    public BaseTestAESGCMCICOWithGCM(String providerName, int keySize) throws Exception {

        super(providerName);
        this.specifiedKeySize = keySize;
        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= keySize);
    }

    public void testDefault() throws Exception {
        dotestAESGCMCICOWithGCM(specifiedKeySize);
    }

    public void testAESGCMCICOWithGCM128() throws Exception {
        dotestAESGCMCICOWithGCM(128);
    }

    public void testAESGCMCICOWithGCM192() throws Exception {
        dotestAESGCMCICOWithGCM(192);
    }

    public void testAESGCMCICOWithGCM256() throws Exception {
        dotestAESGCMCICOWithGCM(256);
    }

    protected void dotestAESGCMCICOWithGCM(int myKeysize) throws Exception {
        int LEN = 100;
        KeyGenerator kg = KeyGenerator.getInstance("AES", providerName);
        kg.init(myKeysize);
        SecretKey key = kg.generateKey();

        System.out.println("Got the " + myKeysize + " bit key");
        //do initialization of the plainText
        byte[] plainText = new byte[LEN];
        Random rdm = new Random();
        rdm.nextBytes(plainText);

        //init ciphers
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        encCipher.init(Cipher.ENCRYPT_MODE, key);

        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        decCipher.init(Cipher.DECRYPT_MODE, key, encCipher.getParameters());


        //init cipher streams
        ByteArrayInputStream baInput = new ByteArrayInputStream(plainText);
        CipherInputStream ciInput = new CipherInputStream(baInput, encCipher);
        ByteArrayOutputStream baOutput = new ByteArrayOutputStream();
        CipherOutputStream ciOutput = new CipherOutputStream(baOutput, decCipher);

        //do test
        byte[] buffer = new byte[LEN];
        int len = ciInput.read(buffer);

        while (len != -1) {

            ciOutput.write(buffer, 0, len);

            len = ciInput.read(buffer);

        }

        ciOutput.flush();
        ciInput.close();
        ciOutput.close();
        byte[] recovered = baOutput.toByteArray();

        if (!Arrays.equals(plainText, recovered)) {
            assertTrue("diff check failed!", false);
        } else {
            assertTrue("diff check passed", true);
        }
    }

}
