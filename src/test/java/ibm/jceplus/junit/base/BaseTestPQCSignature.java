/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

public class BaseTestPQCSignature extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    @ParameterizedTest
    @CsvSource({"ML_DSA_44","ML-DSA-65","ML_DSA_87"})
    public void testPQCKeySignature(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);
        doSignVerify(Algorithm, origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @ParameterizedTest
    @CsvSource({"ML_DSA_44","ML-DSA-65","ML_DSA_87"})
    public void testPQCKeySignatureEncodings(String Algorithm) throws Exception {

        KeyPair keyPair = generateKeyPair(Algorithm);

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] publicKeyBytes = publicKey.getEncoded();
        byte[] privateKeyBytes = privateKey.getEncoded();

        KeyFactory keyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        doSignVerify(Algorithm, origMsg, keyFactory.generatePrivate(privateKeySpec), keyFactory.generatePublic(publicKeySpec));
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        KeyPairGenerator pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        return pqcKeyPairGen.generateKeyPair();
    }

}

