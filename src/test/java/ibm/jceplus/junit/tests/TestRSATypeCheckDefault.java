/*
 * Copyright IBM Corp. 2023, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestRSATypeCheckDefault extends BaseTest {

    @Parameter(0)
    TestProvider provider;

    static final int DEFAULT_KEY_SIZE = 2048;

    KeyPairGenerator rsaKeyPairGen;
    KeyPair rsaKeyPair;
    RSAPublicKey rsaPub;
    RSAPrivateCrtKey rsaPriv;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGen.initialize(DEFAULT_KEY_SIZE, null);
        rsaKeyPair = rsaKeyPairGen.generateKeyPair();
        rsaPub = (RSAPublicKey) rsaKeyPair.getPublic();
        rsaPriv = (RSAPrivateCrtKey) rsaKeyPair.getPrivate();
    }

    @Test
    public void testPrivateKeyEncrypt() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", getProviderName());
            cp.init(Cipher.ENCRYPT_MODE, rsaPriv);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException ike) {
            assertTrue(true);
        }
    }

    @Test
    public void testPublicKeyDecrypt() throws Exception {
        try {
            Cipher cp = Cipher.getInstance("RSA", getProviderName());
            cp.init(Cipher.DECRYPT_MODE, rsaPub);
            fail("Expected InvalidKeyException did not occur");
        } catch (InvalidKeyException ike) {
            assertTrue(true);
        }
    }
}
