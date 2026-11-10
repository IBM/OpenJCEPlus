/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunRsaSignInteropProvider")
public class TestRSASignatureInteropSunRsaSign extends BaseTestSignatureInterop {

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    static final byte[] origMsg = "this is the original message to be signed I changed to a very long message to make sure enough bytes are there for copying."
            .getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
        // FIPS does not support 1024 bit keys
        setKeySize("OpenJCEPlusFIPS".equals(getProviderName()) ? 2048 : 1024);
    }

    @Test
    public void testSHA1withRSA() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support SHA1
            return;
        }
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA1withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA224withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA256withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA384withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA384withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA512withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA512withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }


    /*
    RSAforSSL is not supported in other cryptographic providers in order to do interopt testing

    @Test
    public void testRSAforSSL_hash1() throws Exception {
        KeyPair keyPair = generateKeyPair( getKeySize());
        byte[]  sslHash = Arrays.copyOf(origMsg, 1);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Test
    public void testRSAforSSL_hash5() throws Exception {
        KeyPair keyPair = generateKeyPair( getKeySize());
        byte[]  sslHash = Arrays.copyOf(origMsg, 5);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Test
    public void testRSAforSSL_hash20() throws Exception {
        KeyPair keyPair = generateKeyPair( getKeySize());
        byte[]  sslHash = Arrays.copyOf(origMsg, 20);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Test
    public void testRSAforSSL_hash36() throws Exception {
        KeyPair keyPair = generateKeyPair( getKeySize());
        byte[]  sslHash = Arrays.copyOf(origMsg, 36);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }


    @Test
    public void testRSAforSSL_hash40() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[]  sslHash = Arrays.copyOf(origMsg, 40);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }
    */

    private KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }
}

