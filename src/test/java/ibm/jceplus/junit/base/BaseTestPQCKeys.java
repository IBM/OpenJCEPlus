/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

public class BaseTestPQCKeys extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

    private static final String RFC9881_ML_DSA_44_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMRBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_65_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMSBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9881_ML_DSA_87_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MDQCAQAwCwYJYIZIAWUDBAMTBCKAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4f
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_512_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQBBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_768_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQCBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    private static final String RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED = """
            -----BEGIN PRIVATE KEY-----
            MFQCAQAwCwYJYIZIAWUDBAQDBEKAQAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZ
            GhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=
            -----END PRIVATE KEY-----
            """;

    @BeforeEach
    public void setUp() throws Exception {
    }

    @ParameterizedTest
    @CsvSource({
        // canonical family names
        "ML-KEM", "ML-DSA",
        // canonical param-set names
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
        // underscore aliases
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        "ML_DSA_44",  "ML_DSA_65",  "ML_DSA_87",
        // compact (no-separator) aliases
        "MLKEM512", "MLKEM768", "MLKEM1024",
        "MLDSA44",  "MLDSA65",  "MLDSA87",
        // mixed-case: hyphenated lowercase
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "ml-dsa-44",  "ml-dsa-65",  "ml-dsa-87",
        // mixed-case: hyphenated title-case
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        "Ml-Dsa-44",  "Ml-Dsa-65",  "Ml-Dsa-87",
        // mixed-case: underscore lowercase
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        "ml_dsa_44",  "ml_dsa_65",  "ml_dsa_87",
        // mixed-case: compact lowercase
        "mlkem512", "mlkem768", "mlkem1024",
        "mldsa44",  "mldsa65",  "mldsa87",
        // mixed-case: compact camelCase
        "MlKem512", "MlKem768", "MlKem1024",
        "MlDsa44",  "MlDsa65",  "MlDsa87",
        // bare OID strings (dotted-arc notation)
        "2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.3",
        "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19"
    })
    public void testPQCKeyGen(String Algorithm) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        try {
            KeyPair pqcKeyPair = generateKeyPair(Algorithm);

            pqcKeyPair.getPublic();
            pqcKeyPair.getPrivate();
        } catch (Exception e) {
            throw new Exception(e.getCause() + " - " + Algorithm, e);
        }
    }

    @ParameterizedTest
    @CsvSource({
        // canonical family names
        "ML-KEM", "ML-DSA",
        // canonical param-set names
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
        // underscore aliases
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        "ML_DSA_44",  "ML_DSA_65",  "ML_DSA_87",
        // compact (no-separator) aliases
        "MLKEM512", "MLKEM768", "MLKEM1024",
        "MLDSA44",  "MLDSA65",  "MLDSA87",
        // mixed-case: hyphenated lowercase
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "ml-dsa-44",  "ml-dsa-65",  "ml-dsa-87",
        // mixed-case: hyphenated title-case
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        "Ml-Dsa-44",  "Ml-Dsa-65",  "Ml-Dsa-87",
        // mixed-case: underscore lowercase
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        "ml_dsa_44",  "ml_dsa_65",  "ml_dsa_87",
        // mixed-case: compact lowercase
        "mlkem512", "mlkem768", "mlkem1024",
        "mldsa44",  "mldsa65",  "mldsa87",
        // mixed-case: compact camelCase
        "MlKem512", "MlKem768", "MlKem1024",
        "MlDsa44",  "MlDsa65",  "MlDsa87",
        // OID.xxx-prefixed aliases (as registered in provider)
        "OID.2.16.840.1.101.3.4.4.1", "OID.2.16.840.1.101.3.4.4.2", "OID.2.16.840.1.101.3.4.4.3",
        "OID.2.16.840.1.101.3.4.3.17", "OID.2.16.840.1.101.3.4.3.18", "OID.2.16.840.1.101.3.4.3.19",
        // mixed-case OID prefix (JCA strips "OID." case-insensitively)
        "oid.2.16.840.1.101.3.4.4.1", "oid.2.16.840.1.101.3.4.4.2", "oid.2.16.840.1.101.3.4.4.3",
        "oid.2.16.840.1.101.3.4.3.17", "oid.2.16.840.1.101.3.4.3.18", "oid.2.16.840.1.101.3.4.3.19",
        // bare OID strings
        "2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.3",
        "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19"
    })
    public void testPQCKeyFactoryCreateFromEncoded(String Algorithm) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
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

    /**
     * Tests that the generic "ML-DSA" KeyFactory can decode public and private
     * keys originally generated with any specific ML-DSA parameter set.
     * <p>
     * Per JEP 497, KeyFactory.getInstance("ML-DSA") must accept keys from all
     * ML-DSA parameter sets (ML-DSA-44, ML-DSA-65, ML-DSA-87).  Currently
     * OpenJCEPlus maps the "ML-DSA" alias to ML-DSA-65 only, so decoding
     * ML-DSA-44 or ML-DSA-87 keys through the generic factory fails.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSAKeyFactoryDecodesAllParamSets(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate a key pair using the specific parameter-set name
        KeyPair kp = generateKeyPair(paramSetName);
        byte[] x509Bytes  = kp.getPublic().getEncoded();
        byte[] pkcs8Bytes = kp.getPrivate().getEncoded();

        // Obtain a generic "ML-DSA" KeyFactory (family name, not param-set)
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());

        // Public key decode via generic KF must succeed for all param sets
        PublicKey pub;
        try {
            pub = genericKF.generatePublic(new X509EncodedKeySpec(x509Bytes));
        } catch (InvalidKeySpecException e) {
            fail("Generic ML-DSA KeyFactory failed to decode " + paramSetName
                    + " public key: " + e.getMessage());
            return;
        }
        assertArrayEquals(x509Bytes, pub.getEncoded(),
                "Re-encoded public key bytes differ for " + paramSetName);

        // Private key decode via generic KF must succeed for all param sets
        PrivateKey priv;
        try {
            priv = genericKF.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
        } catch (InvalidKeySpecException e) {
            fail("Generic ML-DSA KeyFactory failed to decode " + paramSetName
                    + " private key: " + e.getMessage());
            return;
        }
        assertArrayEquals(pkcs8Bytes, priv.getEncoded(),
                "Re-encoded private key bytes differ for " + paramSetName);
    }

    /**
     * Tests that key.getAlgorithm() returns the family name "ML-DSA" for keys
     * generated with any ML-DSA parameter set, matching the SUN provider
     * behaviour described in JEP 497.
     */
    @ParameterizedTest
    @CsvSource({
        // canonical names
        "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        // underscore aliases
        "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
        // compact aliases
        "MLDSA44", "MLDSA65", "MLDSA87",
        // mixed-case: hyphenated lowercase
        "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
        // mixed-case: hyphenated title-case
        "Ml-Dsa-44", "Ml-Dsa-65", "Ml-Dsa-87",
        // mixed-case: underscore lowercase
        "ml_dsa_44", "ml_dsa_65", "ml_dsa_87",
        // mixed-case: compact lowercase / camelCase
        "mldsa44", "mldsa65", "mldsa87",
        "MlDsa44", "MlDsa65", "MlDsa87"
    })
    public void testMLDSAKeyAlgorithmReturnsFamilyName(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair(paramSetName);

        assertEquals("ML-DSA", kp.getPublic().getAlgorithm(),
                "getAlgorithm() on public key generated with " + paramSetName
                        + " should return family name \"ML-DSA\"");
        assertEquals("ML-DSA", kp.getPrivate().getAlgorithm(),
                "getAlgorithm() on private key generated with " + paramSetName
                        + " should return family name \"ML-DSA\"");
    }

    /**
     * Tests that key.getAlgorithm() returns the family name "ML-KEM" for keys
     * generated with any ML-KEM parameter set, matching the SUN provider
     * behaviour which is "ML-KEM" for all three ML-KEM parameter sets.
     */
    @ParameterizedTest
    @CsvSource({
        // canonical names
        "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        // underscore aliases
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        // compact aliases
        "MLKEM512", "MLKEM768", "MLKEM1024",
        // mixed-case: hyphenated lowercase
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        // mixed-case: hyphenated title-case
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        // mixed-case: underscore lowercase
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        // mixed-case: compact lowercase / camelCase
        "mlkem512", "mlkem768", "mlkem1024",
        "MlKem512", "MlKem768", "MlKem1024"
    })
    public void testMLKEMKeyAlgorithmReturnsFamilyName(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair(paramSetName);

        assertEquals("ML-KEM", kp.getPublic().getAlgorithm(),
                "getAlgorithm() on public key generated with " + paramSetName
                        + " should return family name \"ML-KEM\"");
        assertEquals("ML-KEM", kp.getPrivate().getAlgorithm(),
                "getAlgorithm() on private key generated with " + paramSetName
                        + " should return family name \"ML-KEM\"");
    }

    /**
     * Tests that {@code KeyPairGenerator.getInstance("ML-DSA")} produces an
     * ML-DSA-65 key by default — i.e. when no {@code AlgorithmParameterSpec} is
     * passed to {@code initialize()}.
     *
     * <p>This matches the SUN provider behaviour (comment in ML_DSA_Impls.KPG:
     * "ML-DSA-65 is default") and the OpenJCEPlus implementation in
     * {@link com.ibm.crypto.plus.provider.PQCKeyPairGenerator#generateKeyPair()}.
     *
     * <p>The test verifies the default by:
     * <ol>
     *   <li>Generating a key pair without calling {@code initialize()}</li>
     *   <li>Checking that the encoded public key is the same length as one
     *       explicitly generated with {@code ML-DSA-65}</li>
     *   <li>Confirming that the generic {@code KeyFactory("ML-DSA")} can round-trip
     *       the key and that the re-decoded key is accepted by the ML-DSA-65
     *       specific {@code KeyFactory} (which rejects ML-DSA-44 and ML-DSA-87)</li>
     * </ol>
     */
    @Test
    public void testMLDSADefaultParamSetIsML_DSA_65() throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate without calling initialize() — should silently default to ML-DSA-65
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA", getProviderName());
        KeyPair defaultKp = kpg.generateKeyPair();

        // Generate an explicit ML-DSA-65 key for byte-length comparison
        KeyPair ml65Kp = generateKeyPair("ML-DSA-65");

        assertEquals(ml65Kp.getPublic().getEncoded().length,
                defaultKp.getPublic().getEncoded().length,
                "Default ML-DSA public key length should equal ML-DSA-65 public key length");
        assertEquals(ml65Kp.getPrivate().getEncoded().length,
                defaultKp.getPrivate().getEncoded().length,
                "Default ML-DSA private key length should equal ML-DSA-65 private key length");

        // The family-name KF must accept the default key
        KeyFactory genericKF  = KeyFactory.getInstance("ML-DSA",    getProviderName());
        KeyFactory specificKF = KeyFactory.getInstance("ML-DSA-65", getProviderName());

        // Round-trip through generic KF
        PublicKey  pubRound  = genericKF.generatePublic(
                new X509EncodedKeySpec(defaultKp.getPublic().getEncoded()));
        PrivateKey privRound = genericKF.generatePrivate(
                new PKCS8EncodedKeySpec(defaultKp.getPrivate().getEncoded()));

        assertArrayEquals(defaultKp.getPublic().getEncoded(), pubRound.getEncoded(),
                "Generic ML-DSA KF: re-encoded public key bytes should be identical");
        assertArrayEquals(defaultKp.getPrivate().getEncoded(), privRound.getEncoded(),
                "Generic ML-DSA KF: re-encoded private key bytes should be identical");

        // The ML-DSA-65 specific KF must also accept the default key (proves it is ML-DSA-65)
        try {
            specificKF.generatePublic(
                    new X509EncodedKeySpec(defaultKp.getPublic().getEncoded()));
            specificKF.generatePrivate(
                    new PKCS8EncodedKeySpec(defaultKp.getPrivate().getEncoded()));
        } catch (Exception e) {
            fail("ML-DSA-65 specific KeyFactory rejected the default ML-DSA key — "
                    + "default param set is not ML-DSA-65: " + e.getMessage());
        }
    }

    /**
     * Tests that a generic "ML-DSA" KeyFactory can translateKey() for keys
     * from all three ML-DSA parameter sets.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})
    public void testGenericMLDSAKeyFactoryTranslateKey(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair(paramSetName);
        KeyFactory genericKF = KeyFactory.getInstance("ML-DSA", getProviderName());

        try {
            PublicKey pub = (PublicKey) genericKF.translateKey(kp.getPublic());
            assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(),
                    "translateKey public key bytes differ for " + paramSetName);
        } catch (InvalidKeyException e) {
            fail("Generic ML-DSA KeyFactory.translateKey() failed for "
                    + paramSetName + " public key: " + e.getMessage());
        }

        try {
            PrivateKey priv = (PrivateKey) genericKF.translateKey(kp.getPrivate());
            assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(),
                    "translateKey private key bytes differ for " + paramSetName);
        } catch (InvalidKeyException e) {
            fail("Generic ML-DSA KeyFactory.translateKey() failed for "
                    + paramSetName + " private key: " + e.getMessage());
        }
    }

    /**
     * Tests that a param-set-specific KeyFactory rejects a key that belongs
     * to a different ML-DSA parameter set, matching SUN provider behaviour.
     * For example, KeyFactory.getInstance("ML-DSA-44") must throw
     * InvalidKeyException when asked to translate an ML-DSA-65 key.
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA-44, ML-DSA-65",
                "ML-DSA-44, ML-DSA-87",
                "ML-DSA-65, ML-DSA-44",
                "ML-DSA-65, ML-DSA-87",
                "ML-DSA-87, ML-DSA-44",
                "ML-DSA-87, ML-DSA-65"})
    public void testSpecificMLDSAKeyFactoryRejectsWrongParamSet(
            String kfParamSet, String keyParamSet) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        KeyPair kp = generateKeyPair(keyParamSet);
        byte[] x509Bytes  = kp.getPublic().getEncoded();
        byte[] pkcs8Bytes = kp.getPrivate().getEncoded();

        KeyFactory specificKF = KeyFactory.getInstance(kfParamSet, getProviderName());

        String expectedCauseMsg = "Expected a " + kfParamSet + " key, but got " + keyParamSet;

        try {
            specificKF.generatePublic(new X509EncodedKeySpec(x509Bytes));
            fail("KeyFactory(" + kfParamSet + ") should reject " + keyParamSet
                    + " public key but did not");
        } catch (InvalidKeySpecException e) {
            assertEquals("Inappropriate key specification: ", e.getMessage());
            assertNotNull(e.getCause(), "Expected a cause on the InvalidKeySpecException");
            assertEquals(expectedCauseMsg, e.getCause().getMessage());
        }

        try {
            specificKF.generatePrivate(new PKCS8EncodedKeySpec(pkcs8Bytes));
            fail("KeyFactory(" + kfParamSet + ") should reject " + keyParamSet
                    + " private key but did not");
        } catch (InvalidKeySpecException e) {
            assertEquals("Inappropriate key specification: ", e.getMessage());
            assertNotNull(e.getCause(), "Expected a cause on the InvalidKeySpecException");
            assertEquals(expectedCauseMsg, e.getCause().getMessage());
        }
    }

    @ParameterizedTest
    @MethodSource("rfcSeedPrivateKeys")
    public void testRFC9881MLDSARFC9935MLKEMKeyFactory(String algorithm, String privateKeyPem) throws Exception {

        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        byte[] rfcPrivateKeyEncoded = decodePEM(privateKeyPem);

        String expectedMessage = "Only expanded keys are supported by OpenJCEPlus";
        try {
            openjceplusKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));
            fail("Expected InvalidKeySpecException for seed-only private key.");
        } catch (InvalidKeySpecException e) {
            assertEquals(expectedMessage, e.getCause().getMessage());
        }
    }

    private static Stream<Arguments> rfcSeedPrivateKeys() {
        return Stream.of(
                Arguments.of("ML-DSA-44",
                        RFC9881_ML_DSA_44_PRIVATE_KEY_SEED),
                Arguments.of("ML-DSA-65",
                        RFC9881_ML_DSA_65_PRIVATE_KEY_SEED),
                Arguments.of("ML-DSA-87",
                        RFC9881_ML_DSA_87_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-512",
                        RFC9935_ML_KEM_512_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-768",
                        RFC9935_ML_KEM_768_PRIVATE_KEY_SEED),
                Arguments.of("ML-KEM-1024",
                        RFC9935_ML_KEM_1024_PRIVATE_KEY_SEED)
        );
    }

    /**
     * Verifies that the OID embedded in the DER-encoded public and private key
     * matches the NIST-assigned OID for every supported PQC algorithm.
     *
     * <p>The X.509 SubjectPublicKeyInfo structure encodes the AlgorithmIdentifier
     * as the first inner SEQUENCE, with the OID at a fixed offset of 4 bytes in.
     * The PKCS#8 OneAsymmetricKey structure places the OID at offset 9.
     * Both are checked here to ensure {@link com.ibm.crypto.plus.provider.PQCKnownOIDs}
     * and {@link com.ibm.crypto.plus.provider.PQCAlgorithmId} agree with the standard.
     *
     * <p>OID values are from NIST FIPS 203/204/205:
     * <ul>
     *   <li>ML-KEM-512:  2.16.840.1.101.3.4.4.1  → 6086480165030404 01</li>
     *   <li>ML-KEM-768:  2.16.840.1.101.3.4.4.2  → 6086480165030404 02</li>
     *   <li>ML-KEM-1024: 2.16.840.1.101.3.4.4.3  → 6086480165030404 03</li>
     *   <li>ML-DSA-44:   2.16.840.1.101.3.4.3.17 → 6086480165030403 11</li>
     *   <li>ML-DSA-65:   2.16.840.1.101.3.4.3.18 → 6086480165030403 12</li>
     *   <li>ML-DSA-87:   2.16.840.1.101.3.4.3.19 → 6086480165030403 13</li>
     * </ul>
     */
    @ParameterizedTest
    @CsvSource({
        // algorithm,               expected OID hex (9 bytes, no spaces)
        "ML-KEM-512,           608648016503040401",
        "ML-KEM-768,           608648016503040402",
        "ML-KEM-1024,          608648016503040403",
        // Generic ML-KEM name defaults to ML-KEM-768 (OID 2.16.840.1.101.3.4.4.2)
        "ML-KEM,               608648016503040402",
        "ML-DSA-44,            608648016503040311",
        "ML-DSA-65,            608648016503040312",
        "ML-DSA-87,            608648016503040313",
        // Generic ML-DSA name defaults to ML-DSA-65 (OID 2.16.840.1.101.3.4.3.18)
        "ML-DSA,               608648016503040312"
    })
    public void testEncodedKeyContainsCorrectOID(String algorithm, String expectedOidHex)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Strip any whitespace introduced by CsvSource padding
        expectedOidHex = expectedOidHex.strip();

        KeyPair kp = generateKeyPair(algorithm);

        // --- Public key (X.509 SubjectPublicKeyInfo) ---
        // These keys are large so the outer SEQUENCE uses a 2-byte length:
        //   30 82 xx xx  -- outer SEQUENCE (4-byte header)
        //   30 0b        -- AlgorithmIdentifier SEQUENCE at byte offset 4
        //   06 09        -- OID tag + length at byte offset 6
        //   <9 bytes>    -- OID value starting at byte offset 8
        byte[] x509 = kp.getPublic().getEncoded();
        String x509hex = BaseUtils.bytesToHex(x509);
        // hex chars: each byte = 2 chars; OID tag+len at hex offset 12 (bytes 6–7)
        assertEquals("0609", x509hex.substring(12, 16),
                "X.509 encoding for " + algorithm + " should contain OID tag 06, length 09");
        String actualPublicOid = x509hex.substring(16, 34); // 9 bytes × 2 hex chars = 18 chars
        assertEquals(expectedOidHex, actualPublicOid,
                "X.509 OID mismatch for " + algorithm);

        // --- Private key (PKCS#8 OneAsymmetricKey) ---
        // These keys are large so both the outer SEQUENCE and the AlgId are long-form:
        //   30 82 xx xx  -- outer SEQUENCE (4-byte header)
        //   02 01 00     -- version INTEGER 0 at byte offset 4
        //   30 0b        -- AlgorithmIdentifier SEQUENCE at byte offset 7
        //   06 09        -- OID tag + length at byte offset 9
        //   <9 bytes>    -- OID value starting at byte offset 11
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        String pkcs8hex = BaseUtils.bytesToHex(pkcs8);
        // hex offset 18 = byte offset 9 (OID tag+len)
        assertEquals("0609", pkcs8hex.substring(18, 22),
                "PKCS#8 encoding for " + algorithm + " should contain OID tag 06, length 09");
        String actualPrivateOid = pkcs8hex.substring(22, 40); // 9 bytes × 2 hex chars = 18 chars
        assertEquals(expectedOidHex, actualPrivateOid,
                "PKCS#8 OID mismatch for " + algorithm);

        // Verify the key round-trips correctly through KeyFactory using the embedded OID
        KeyFactory kf = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey  pub2  = kf.generatePublic(new X509EncodedKeySpec(x509));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        assertArrayEquals(x509,  pub2.getEncoded(),  "Public key round-trip failed for "  + algorithm);
        assertArrayEquals(pkcs8, priv2.getEncoded(), "Private key round-trip failed for " + algorithm);

        // Confirm getAlgorithm() returns the expected family name
        String expectedFamily = algorithm.startsWith("ML-KEM") ? "ML-KEM"
                              : algorithm.startsWith("ML-DSA") ? "ML-DSA"
                              : algorithm; // SLH-DSA variants have no family alias yet
        assertEquals(expectedFamily, pub2.getAlgorithm(),
                "getAlgorithm() family name mismatch on public key for " + algorithm);
        assertEquals(expectedFamily, priv2.getAlgorithm(),
                "getAlgorithm() family name mismatch on private key for " + algorithm);
    }

    /**
     * Verifies that all registered OID alias forms for {@code KeyFactory} resolve
     * to the correct param-set service and can successfully round-trip a key pair.
     *
     * <p>For each param-set the provider registers four alias forms in addition to
     * the canonical hyphenated name:
     * <ul>
     *   <li>Underscore name  — e.g. {@code ML_KEM_512}</li>
     *   <li>Compact name     — e.g. {@code MLKEM512}</li>
     *   <li>{@code OID.xxx}  — e.g. {@code OID.2.16.840.1.101.3.4.4.1}</li>
     *   <li>Bare OID string  — e.g. {@code 2.16.840.1.101.3.4.4.1}</li>
     * </ul>
     * Each alias is used as the argument to {@code KeyFactory.getInstance()} and
     * the resulting factory must correctly decode an encoded key previously
     * generated with the canonical param-set name.
     *
     * <p>Parameters are: alias, canonical param-set name used to generate the key,
     * expected family name returned by {@link java.security.Key#getAlgorithm()}.
     */
    @ParameterizedTest
    @MethodSource("keyFactoryOidAliasArgs")
    public void testKeyFactoryOidAliasRoundTrip(
            String alias, String canonicalParamSet, String expectedFamily)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        // Generate with the canonical param-set name so we have a known key
        KeyPair kp = generateKeyPair(canonicalParamSet);
        byte[] x509bytes  = kp.getPublic().getEncoded();
        byte[] pkcs8bytes = kp.getPrivate().getEncoded();

        // Obtain a KeyFactory through the alias name — this is what we are testing
        KeyFactory kf = KeyFactory.getInstance(alias, getProviderName());

        PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(x509bytes));
        assertArrayEquals(x509bytes, pub.getEncoded(),
                "KeyFactory(\"" + alias + "\") public key round-trip failed");
        assertEquals(expectedFamily, pub.getAlgorithm(),
                "KeyFactory(\"" + alias + "\") public key getAlgorithm() mismatch");

        PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8bytes));
        assertArrayEquals(pkcs8bytes, priv.getEncoded(),
                "KeyFactory(\"" + alias + "\") private key round-trip failed");
        assertEquals(expectedFamily, priv.getAlgorithm(),
                "KeyFactory(\"" + alias + "\") private key getAlgorithm() mismatch");
    }

    private static Stream<Arguments> keyFactoryOidAliasArgs() {
        // Each row: alias, canonical param-set, expected getAlgorithm() family
        return Stream.of(
            // ---- ML-KEM-512 aliases ----
            Arguments.of("ML_KEM_512",                    "ML-KEM-512",  "ML-KEM"),
            Arguments.of("MLKEM512",                      "ML-KEM-512",  "ML-KEM"),
            Arguments.of("OID.2.16.840.1.101.3.4.4.1",   "ML-KEM-512",  "ML-KEM"),
            Arguments.of("2.16.840.1.101.3.4.4.1",       "ML-KEM-512",  "ML-KEM"),
            // mixed-case ML-KEM-512
            Arguments.of("ml-kem-512",                    "ML-KEM-512",  "ML-KEM"),
            Arguments.of("Ml-Kem-512",                    "ML-KEM-512",  "ML-KEM"),
            Arguments.of("ml_kem_512",                    "ML-KEM-512",  "ML-KEM"),
            Arguments.of("mlkem512",                      "ML-KEM-512",  "ML-KEM"),
            Arguments.of("MlKem512",                      "ML-KEM-512",  "ML-KEM"),
            Arguments.of("oid.2.16.840.1.101.3.4.4.1",   "ML-KEM-512",  "ML-KEM"),
            // ---- ML-KEM-768 aliases ----
            Arguments.of("ML_KEM_768",                    "ML-KEM-768",  "ML-KEM"),
            Arguments.of("MLKEM768",                      "ML-KEM-768",  "ML-KEM"),
            Arguments.of("OID.2.16.840.1.101.3.4.4.2",   "ML-KEM-768",  "ML-KEM"),
            Arguments.of("2.16.840.1.101.3.4.4.2",       "ML-KEM-768",  "ML-KEM"),
            // mixed-case ML-KEM-768
            Arguments.of("ml-kem-768",                    "ML-KEM-768",  "ML-KEM"),
            Arguments.of("Ml-Kem-768",                    "ML-KEM-768",  "ML-KEM"),
            Arguments.of("ml_kem_768",                    "ML-KEM-768",  "ML-KEM"),
            Arguments.of("mlkem768",                      "ML-KEM-768",  "ML-KEM"),
            Arguments.of("MlKem768",                      "ML-KEM-768",  "ML-KEM"),
            Arguments.of("oid.2.16.840.1.101.3.4.4.2",   "ML-KEM-768",  "ML-KEM"),
            // ---- ML-KEM-1024 aliases ----
            Arguments.of("ML_KEM_1024",                   "ML-KEM-1024", "ML-KEM"),
            Arguments.of("MLKEM1024",                     "ML-KEM-1024", "ML-KEM"),
            Arguments.of("OID.2.16.840.1.101.3.4.4.3",   "ML-KEM-1024", "ML-KEM"),
            Arguments.of("2.16.840.1.101.3.4.4.3",       "ML-KEM-1024", "ML-KEM"),
            // mixed-case ML-KEM-1024
            Arguments.of("ml-kem-1024",                   "ML-KEM-1024", "ML-KEM"),
            Arguments.of("Ml-Kem-1024",                   "ML-KEM-1024", "ML-KEM"),
            Arguments.of("ml_kem_1024",                   "ML-KEM-1024", "ML-KEM"),
            Arguments.of("mlkem1024",                     "ML-KEM-1024", "ML-KEM"),
            Arguments.of("MlKem1024",                     "ML-KEM-1024", "ML-KEM"),
            Arguments.of("oid.2.16.840.1.101.3.4.4.3",   "ML-KEM-1024", "ML-KEM"),
            // ---- ML-DSA-44 aliases ----
            Arguments.of("ML_DSA_44",                     "ML-DSA-44",   "ML-DSA"),
            Arguments.of("MLDSA44",                       "ML-DSA-44",   "ML-DSA"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.17",  "ML-DSA-44",   "ML-DSA"),
            Arguments.of("2.16.840.1.101.3.4.3.17",      "ML-DSA-44",   "ML-DSA"),
            // mixed-case ML-DSA-44
            Arguments.of("ml-dsa-44",                     "ML-DSA-44",   "ML-DSA"),
            Arguments.of("Ml-Dsa-44",                     "ML-DSA-44",   "ML-DSA"),
            Arguments.of("ml_dsa_44",                     "ML-DSA-44",   "ML-DSA"),
            Arguments.of("mldsa44",                       "ML-DSA-44",   "ML-DSA"),
            Arguments.of("MlDsa44",                       "ML-DSA-44",   "ML-DSA"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.17",  "ML-DSA-44",   "ML-DSA"),
            // ---- ML-DSA-65 aliases ----
            Arguments.of("ML_DSA_65",                     "ML-DSA-65",   "ML-DSA"),
            Arguments.of("MLDSA65",                       "ML-DSA-65",   "ML-DSA"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.18",  "ML-DSA-65",   "ML-DSA"),
            Arguments.of("2.16.840.1.101.3.4.3.18",      "ML-DSA-65",   "ML-DSA"),
            // mixed-case ML-DSA-65
            Arguments.of("ml-dsa-65",                     "ML-DSA-65",   "ML-DSA"),
            Arguments.of("Ml-Dsa-65",                     "ML-DSA-65",   "ML-DSA"),
            Arguments.of("ml_dsa_65",                     "ML-DSA-65",   "ML-DSA"),
            Arguments.of("mldsa65",                       "ML-DSA-65",   "ML-DSA"),
            Arguments.of("MlDsa65",                       "ML-DSA-65",   "ML-DSA"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.18",  "ML-DSA-65",   "ML-DSA"),
            // ---- ML-DSA-87 aliases ----
            Arguments.of("ML_DSA_87",                     "ML-DSA-87",   "ML-DSA"),
            Arguments.of("MLDSA87",                       "ML-DSA-87",   "ML-DSA"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.19",  "ML-DSA-87",   "ML-DSA"),
            Arguments.of("2.16.840.1.101.3.4.3.19",      "ML-DSA-87",   "ML-DSA"),
            // mixed-case ML-DSA-87
            Arguments.of("ml-dsa-87",                     "ML-DSA-87",   "ML-DSA"),
            Arguments.of("Ml-Dsa-87",                     "ML-DSA-87",   "ML-DSA"),
            Arguments.of("ml_dsa_87",                     "ML-DSA-87",   "ML-DSA"),
            Arguments.of("mldsa87",                       "ML-DSA-87",   "ML-DSA"),
            Arguments.of("MlDsa87",                       "ML-DSA-87",   "ML-DSA"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.19",  "ML-DSA-87",   "ML-DSA")
        );
    }

    /**
     * Verifies that all registered OID alias forms for the ML-DSA {@code Signature}
     * service resolve to the correct param-set implementation and can sign and
     * verify a message.
     *
     * <p>The provider registers four alias forms per ML-DSA param-set:
     * {@code ML_DSA_44}, {@code MLDSA44}, {@code OID.2.16.840.1.101.3.4.3.17},
     * and {@code 2.16.840.1.101.3.4.3.17} (and equivalent for -65 and -87).
     *
     * <p>Parameters: alias, canonical param-set name used to generate the signing key.
     */
    @ParameterizedTest
    @MethodSource("signatureOidAliasArgs")
    public void testMLDSASignatureOidAliasWorks(String alias, String canonicalParamSet)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));

        byte[] msg = "test message for OID alias signature".getBytes();

        KeyPair kp = generateKeyPair(canonicalParamSet);

        // Sign using the alias name — verifies getInstance() resolves correctly
        Signature signer = Signature.getInstance(alias, getProviderName());
        signer.initSign(kp.getPrivate());
        signer.update(msg);
        byte[] sig = signer.sign();

        // Verify using the same alias
        Signature verifier = Signature.getInstance(alias, getProviderName());
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig),
                "Signature.getInstance(\"" + alias + "\") verify failed for "
                        + canonicalParamSet);
    }

    private static Stream<Arguments> signatureOidAliasArgs() {
        // Each row: alias, canonical param-set name used to generate the key pair
        return Stream.of(
            // ---- ML-DSA-44 aliases ----
            Arguments.of("ML_DSA_44",                    "ML-DSA-44"),
            Arguments.of("MLDSA44",                      "ML-DSA-44"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
            Arguments.of("2.16.840.1.101.3.4.3.17",     "ML-DSA-44"),
            // mixed-case ML-DSA-44
            Arguments.of("ml-dsa-44",                    "ML-DSA-44"),
            Arguments.of("Ml-Dsa-44",                    "ML-DSA-44"),
            Arguments.of("ml_dsa_44",                    "ML-DSA-44"),
            Arguments.of("mldsa44",                      "ML-DSA-44"),
            Arguments.of("MlDsa44",                      "ML-DSA-44"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.17", "ML-DSA-44"),
            // ---- ML-DSA-65 aliases ----
            Arguments.of("ML_DSA_65",                    "ML-DSA-65"),
            Arguments.of("MLDSA65",                      "ML-DSA-65"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
            Arguments.of("2.16.840.1.101.3.4.3.18",     "ML-DSA-65"),
            // mixed-case ML-DSA-65
            Arguments.of("ml-dsa-65",                    "ML-DSA-65"),
            Arguments.of("Ml-Dsa-65",                    "ML-DSA-65"),
            Arguments.of("ml_dsa_65",                    "ML-DSA-65"),
            Arguments.of("mldsa65",                      "ML-DSA-65"),
            Arguments.of("MlDsa65",                      "ML-DSA-65"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.18", "ML-DSA-65"),
            // ---- ML-DSA-87 aliases ----
            Arguments.of("ML_DSA_87",                    "ML-DSA-87"),
            Arguments.of("MLDSA87",                      "ML-DSA-87"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
            Arguments.of("2.16.840.1.101.3.4.3.19",     "ML-DSA-87"),
            // mixed-case ML-DSA-87
            Arguments.of("ml-dsa-87",                    "ML-DSA-87"),
            Arguments.of("Ml-Dsa-87",                    "ML-DSA-87"),
            Arguments.of("ml_dsa_87",                    "ML-DSA-87"),
            Arguments.of("mldsa87",                      "ML-DSA-87"),
            Arguments.of("MlDsa87",                      "ML-DSA-87"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.19", "ML-DSA-87")
        );
    }

    private static byte[] decodePEM(String pem) {
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
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
