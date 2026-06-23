/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeys extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;



    @BeforeEach
    public void setUp() throws Exception {
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "MLKEM512", "ML_KEM_768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA", "ML_DSA_44", "ML_DSA_65", "ML-DSA-87"})
    public void testPQCKeyGen(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        try {
            KeyPair pqcKeyPair = generateKeyPair(Algorithm);

            pqcKeyPair.getPublic();
            pqcKeyPair.getPrivate();
        } catch (Exception e) {
            throw new Exception(e.getCause() + " - " + Algorithm, e);
        }
    }

    @ParameterizedTest
    @CsvSource({"ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML-DSA", "ML_DSA_44", "ML_DSA_65", "ML-DSA-87"})
    public void testPQCKeyFactoryCreateFromEncoded(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        keyFactoryCreateFromEncoded(Algorithm);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-KEM", "ML-KEM-512"})
    public void generatePublicWithInvalidKeySpec(String algorithm) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] encodedKey = generateKeyPair(algorithm).getPrivate().getEncoded();

        //Pass private key bytes to x509 spec as invalid key bytes
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            keyFactory.generatePublic(publicKeySpec);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidKeySpecException e) {
            // this is expected
        }

    }

    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"})
    public void genWithAlgParameterSpecMLKEM(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", getProviderName());        
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        kpg.initialize(param);
        kpg.generateKeyPair();
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void genWithAlgParameterSpecMLDSA(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", getProviderName());        
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        kpg.initialize(param);
        kpg.generateKeyPair();
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA-65", "ML-DSA-87"})
    public void genWithAlgParameterSpecMLDSAFaiure(String algParamSpecName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44", getProviderName());        
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        try {
            kpg.initialize(param);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidAlgorithmParameterException e) {
            // Expected
        }

    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null - " + Algorithm);
        }

        if (keyPair.getPublic() == null) {
            fail("Public key is null - " + Algorithm);
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey - " + Algorithm);
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey - " + Algorithm);
        }
        //System.out.println("Pub key - "+Algorithm+ " = "+HexFormat.of().formatHex(((com.ibm.crypto.plus.provider.PQCPublicKey)(keyPair.getPublic())).getKeyBytes()));
        //System.out.println("Priv key - "+Algorithm+ " = "+HexFormat.of().formatHex(((com.ibm.crypto.plus.provider.PQCPrivateKey)(keyPair.getPrivate())).getKeyBytes()));
 
        return keyPair;
    }

    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {
        
        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());
        PublicKey pub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv =  pqcKeyFactory.generatePrivate(pkcs8Spec);

        assertArrayEquals(pub.getEncoded(), pqcKeyPair.getPublic().getEncoded(), "Public key does not match generated public key - " + Algorithm);
        assertArrayEquals(priv.getEncoded(), pqcKeyPair.getPrivate().getEncoded(), "Private key does not match generated public key - " + Algorithm);

    }
}
