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
import java.io.IOException;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.Assume;

public class BaseTestAESGCMCICOWithGCMAndAAD extends BaseTest {
    protected int specifiedKeySize = 128;

    public BaseTestAESGCMCICOWithGCMAndAAD(String providerName) {
        super(providerName);
    }

    public BaseTestAESGCMCICOWithGCMAndAAD(String providerName, int keySize) throws Exception {
        super(providerName);
        this.specifiedKeySize = keySize;
        Assume.assumeTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= keySize);
    }

    public void testGCMWithAAD() throws Exception {
        //init Secret Key
        //KeyGenerator kg = KeyGenerator.getInstance("AES", "SunJCE");
        KeyGenerator kg = KeyGenerator.getInstance("AES", providerName);
        kg.init(specifiedKeySize);
        SecretKey key = kg.generateKey();

        //Do initialization of the plainText
        byte[] plainText = new byte[700];
        Random rdm = new Random();
        rdm.nextBytes(plainText);

        byte[] aad = new byte[128];
        rdm.nextBytes(aad);
        byte[] aad2 = aad.clone();
        aad2[50]++;

        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        encCipher.init(Cipher.ENCRYPT_MODE, key);
        encCipher.updateAAD(aad);
        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding", providerName);
        decCipher.init(Cipher.DECRYPT_MODE, key, encCipher.getParameters());
        decCipher.updateAAD(aad);

        byte[] recovered = doTest(encCipher, decCipher, plainText);
        if (!Arrays.equals(plainText, recovered)) {
            throw new Exception("sameAAD: diff check failed!");
        } else
            System.out.println("sameAAD: passed");

        encCipher.init(Cipher.ENCRYPT_MODE, key);
        encCipher.updateAAD(aad2);

        try {
            recovered = doTest(encCipher, decCipher, plainText);
            if (recovered != null && recovered.length != 0) {
                throw new Exception("diffAAD: no data should be returned!");
            }
        } catch (ProviderException ex) {
            //ex.printStackTrace();
            return;
        } catch (Exception ex) {
            //ex.printStackTrace();
            return;
        }

        throw new Exception("Should have thrown an exception");
    }

    private static byte[] doTest(Cipher encCipher, Cipher decCipher, byte[] plainText)
            throws IOException, ProviderException, AEADBadTagException {
        //init cipher streams
        ByteArrayInputStream baInput = new ByteArrayInputStream(plainText);
        CipherInputStream ciInput = new CipherInputStream(baInput, encCipher);
        ByteArrayOutputStream baOutput = new ByteArrayOutputStream();
        CipherOutputStream ciOutput = new CipherOutputStream(baOutput, decCipher);

        //do test
        byte[] buffer = new byte[700];
        int len = ciInput.read(buffer);

        while (len != -1) {
            ciOutput.write(buffer, 0, len);
            len = ciInput.read(buffer);
        }

        ciOutput.flush();
        ciInput.close();
        ciOutput.close();

        return baOutput.toByteArray();
    }
}
