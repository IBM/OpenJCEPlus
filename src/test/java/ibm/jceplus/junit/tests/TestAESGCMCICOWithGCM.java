/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.OPENJCEPLUS_MULTITHREAD_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestAESGCMCICOWithGCM extends BaseTest {
    
    @Parameter(0)
    TestProvider provider;

    protected int specifiedKeySize = 128;

    @BeforeEach
    public void setUp() throws Exception{
        setAndInsertProvider(provider);
    }

    @Test
    public void testDefault() throws Exception {
        dotestAESGCMCICOWithGCM(specifiedKeySize);
    }

    @Test
    public void testAESGCMCICOWithGCM128() throws Exception {
        dotestAESGCMCICOWithGCM(128);
    }

    @Test
    public void testAESGCMCICOWithGCM192() throws Exception {
        dotestAESGCMCICOWithGCM(192);
    }

    @Test
    public void testAESGCMCICOWithGCM256() throws Exception {
        dotestAESGCMCICOWithGCM(256);
    }

    protected void dotestAESGCMCICOWithGCM(int myKeysize) throws Exception {
        int LEN = 100;
        KeyGenerator kg = KeyGenerator.getInstance("AES", getProviderName());
        kg.init(myKeysize);
        SecretKey key = kg.generateKey();

        System.out.println("Got the " + myKeysize + " bit key");
        //do initialization of the plainText
        byte[] plainText = new byte[LEN];
        Random rdm = new Random();
        rdm.nextBytes(plainText);

        //init ciphers
        Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
        encCipher.init(Cipher.ENCRYPT_MODE, key);

        Cipher decCipher = Cipher.getInstance("AES/GCM/NoPadding", getProviderName());
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
            assertTrue(false, "diff check failed!");
        } else {
            assertTrue(true, "diff check passed");
        }
    }

}
