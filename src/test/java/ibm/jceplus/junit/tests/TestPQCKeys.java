/*
 * Copyright IBM Corp. 2025, 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

@Tag(Tags.OPENJCEPLUS_OPENSSL_NAME)
@Tag(Tags.OPENJCEPLUS_OCK_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getEnabledProviders")
public class TestPQCKeys extends BaseTest {

    @Parameter(0)
    TestProvider provider;

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
        setAndInsertProvider(provider);
    }

    /**
     * Verifies that key pair generation succeeds for all supported algorithm name variants.
     * Covers both '-' and '_' name forms for all ML-KEM, ML-DSA, and SLH-DSA families.
     *
     * @param Algorithm the algorithm name to test
     * @throws Exception if key pair generation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({
        // canonical family names
        "ML-KEM", "ML-DSA", "SLH-DSA",
        // canonical param-set names
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
        // underscore aliases
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        "ML_DSA_44",  "ML_DSA_65",  "ML_DSA_87",
        "SLH_DSA_SHA2_128s", "SLH_DSA_SHA2_128f", "SLH_DSA_SHA2_192s", "SLH_DSA_SHA2_192f",
        "SLH_DSA_SHA2_256s", "SLH_DSA_SHA2_256f", "SLH_DSA_SHAKE_128s", "SLH_DSA_SHAKE_128f",
        "SLH_DSA_SHAKE_192s", "SLH_DSA_SHAKE_192f", "SLH_DSA_SHAKE_256s", "SLH_DSA_SHAKE_256f",
        // compact (no-separator) aliases
        "MLKEM512", "MLKEM768", "MLKEM1024",
        "MLDSA44",  "MLDSA65",  "MLDSA87",
        "SLHDSASHA2128s", "SLHDSASHA2128f", "SLHDSASHA2192s", "SLHDSASHA2192f",
        "SLHDSASHA2256s", "SLHDSASHA2256f", "SLHDSASHAKE128s", "SLHDSASHAKE128f",
        "SLHDSASHAKE192s", "SLHDSASHAKE192f", "SLHDSASHAKE256s", "SLHDSASHAKE256f",
        // mixed-case: hyphenated lowercase
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "ml-dsa-44",  "ml-dsa-65",  "ml-dsa-87",
        "slh-dsa-sha2-128s", "slh-dsa-shake-256f",
        // mixed-case: hyphenated title-case
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        "Ml-Dsa-44",  "Ml-Dsa-65",  "Ml-Dsa-87",
        "Slh-Dsa-Sha2-128s", "Slh-Dsa-Shake-256f",
        // mixed-case: underscore lowercase
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        "ml_dsa_44",  "ml_dsa_65",  "ml_dsa_87",
        "slh_dsa_sha2_128s", "slh_dsa_shake_256f",
        // mixed-case: compact lowercase
        "mlkem512", "mlkem768", "mlkem1024",
        "mldsa44",  "mldsa65",  "mldsa87",
        "slhdsasha2128s", "slhdsashake256f",
        // mixed-case: compact camelCase
        "MlKem512", "MlKem768", "MlKem1024",
        "MlDsa44",  "MlDsa65",  "MlDsa87",
        "SlhDsaSha2128s", "SlhDsaShake256f",
        // bare OID strings (dotted-arc notation)
        "2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.3",
        "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19",
        "2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.21", "2.16.840.1.101.3.4.3.22",
        "2.16.840.1.101.3.4.3.23", "2.16.840.1.101.3.4.3.24", "2.16.840.1.101.3.4.3.25",
        "2.16.840.1.101.3.4.3.26", "2.16.840.1.101.3.4.3.27", "2.16.840.1.101.3.4.3.28",
        "2.16.840.1.101.3.4.3.29", "2.16.840.1.101.3.4.3.30", "2.16.840.1.101.3.4.3.31"
    })
    public void testPQCKeyGen(String Algorithm) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(Algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        try {
            KeyPair pqcKeyPair = generateKeyPair(Algorithm);

            pqcKeyPair.getPublic();
            pqcKeyPair.getPrivate();
        } catch (Exception e) {
            throw new Exception(e.getCause() + " - " + Algorithm, e);
        }
    }

    /**
     * Verifies that a {@link KeyFactory} can reconstruct keys from their encoded forms for all
     * supported algorithm name variants. Covers both '-' and '_' name forms for all ML-KEM,
     * ML-DSA, and SLH-DSA families.
     *
     * @param Algorithm the algorithm name to test
     * @throws Exception if key factory creation or encoding round-trip fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({
        // canonical family names
        "ML-KEM", "ML-DSA", "SLH-DSA",
        // canonical param-set names
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44",  "ML-DSA-65",  "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
        // underscore aliases
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        "ML_DSA_44",  "ML_DSA_65",  "ML_DSA_87",
        "SLH_DSA_SHA2_128s", "SLH_DSA_SHA2_128f", "SLH_DSA_SHA2_192s", "SLH_DSA_SHA2_192f",
        "SLH_DSA_SHA2_256s", "SLH_DSA_SHA2_256f", "SLH_DSA_SHAKE_128s", "SLH_DSA_SHAKE_128f",
        "SLH_DSA_SHAKE_192s", "SLH_DSA_SHAKE_192f", "SLH_DSA_SHAKE_256s", "SLH_DSA_SHAKE_256f",
        // compact (no-separator) aliases
        "MLKEM512", "MLKEM768", "MLKEM1024",
        "MLDSA44",  "MLDSA65",  "MLDSA87",
        "SLHDSASHA2128s", "SLHDSASHA2128f", "SLHDSASHA2192s", "SLHDSASHA2192f",
        "SLHDSASHA2256s", "SLHDSASHA2256f", "SLHDSASHAKE128s", "SLHDSASHAKE128f",
        "SLHDSASHAKE192s", "SLHDSASHAKE192f", "SLHDSASHAKE256s", "SLHDSASHAKE256f",
        // mixed-case: hyphenated lowercase
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "ml-dsa-44",  "ml-dsa-65",  "ml-dsa-87",
        "slh-dsa-sha2-128s", "slh-dsa-shake-256f",
        // mixed-case: hyphenated title-case
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        "Ml-Dsa-44",  "Ml-Dsa-65",  "Ml-Dsa-87",
        "Slh-Dsa-Sha2-128s", "Slh-Dsa-Shake-256f",
        // mixed-case: underscore lowercase
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        "ml_dsa_44",  "ml_dsa_65",  "ml_dsa_87",
        "slh_dsa_sha2_128s", "slh_dsa_shake_256f",
        // mixed-case: compact lowercase
        "mlkem512", "mlkem768", "mlkem1024",
        "mldsa44",  "mldsa65",  "mldsa87",
        "slhdsasha2128s", "slhdsashake256f",
        // mixed-case: compact camelCase
        "MlKem512", "MlKem768", "MlKem1024",
        "MlDsa44",  "MlDsa65",  "MlDsa87",
        "SlhDsaSha2128s", "SlhDsaShake256f",
        // OID.xxx-prefixed aliases (as registered in provider)
        "OID.2.16.840.1.101.3.4.4.1", "OID.2.16.840.1.101.3.4.4.2", "OID.2.16.840.1.101.3.4.4.3",
        "OID.2.16.840.1.101.3.4.3.17", "OID.2.16.840.1.101.3.4.3.18", "OID.2.16.840.1.101.3.4.3.19",
        "OID.2.16.840.1.101.3.4.3.20", "OID.2.16.840.1.101.3.4.3.21", "OID.2.16.840.1.101.3.4.3.22",
        "OID.2.16.840.1.101.3.4.3.23", "OID.2.16.840.1.101.3.4.3.24", "OID.2.16.840.1.101.3.4.3.25",
        "OID.2.16.840.1.101.3.4.3.26", "OID.2.16.840.1.101.3.4.3.27", "OID.2.16.840.1.101.3.4.3.28",
        "OID.2.16.840.1.101.3.4.3.29", "OID.2.16.840.1.101.3.4.3.30", "OID.2.16.840.1.101.3.4.3.31",
        // mixed-case OID prefix (JCA strips "OID." case-insensitively)
        "oid.2.16.840.1.101.3.4.4.1", "oid.2.16.840.1.101.3.4.4.2", "oid.2.16.840.1.101.3.4.4.3",
        "oid.2.16.840.1.101.3.4.3.17", "oid.2.16.840.1.101.3.4.3.18", "oid.2.16.840.1.101.3.4.3.19",
        "oid.2.16.840.1.101.3.4.3.20", "oid.2.16.840.1.101.3.4.3.21", "oid.2.16.840.1.101.3.4.3.22",
        "oid.2.16.840.1.101.3.4.3.23", "oid.2.16.840.1.101.3.4.3.24", "oid.2.16.840.1.101.3.4.3.25",
        "oid.2.16.840.1.101.3.4.3.26", "oid.2.16.840.1.101.3.4.3.27", "oid.2.16.840.1.101.3.4.3.28",
        "oid.2.16.840.1.101.3.4.3.29", "oid.2.16.840.1.101.3.4.3.30", "oid.2.16.840.1.101.3.4.3.31",
        // bare OID strings
        "2.16.840.1.101.3.4.4.1", "2.16.840.1.101.3.4.4.2", "2.16.840.1.101.3.4.4.3",
        "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19",
        "2.16.840.1.101.3.4.3.20", "2.16.840.1.101.3.4.3.21", "2.16.840.1.101.3.4.3.22",
        "2.16.840.1.101.3.4.3.23", "2.16.840.1.101.3.4.3.24", "2.16.840.1.101.3.4.3.25",
        "2.16.840.1.101.3.4.3.26", "2.16.840.1.101.3.4.3.27", "2.16.840.1.101.3.4.3.28",
        "2.16.840.1.101.3.4.3.29", "2.16.840.1.101.3.4.3.30", "2.16.840.1.101.3.4.3.31"
    })
    public void testPQCKeyFactoryCreateFromEncoded(String Algorithm) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(Algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        keyFactoryCreateFromEncoded(Algorithm);
    }

    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-KEM", "ML-KEM-512",
                "SLH-DSA", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"})
    public void generatePublicWithInvalidKeySpec(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] encodedKey = generateKeyPair(algorithm).getPrivate().getEncoded();

        //Pass private key bytes to x509 spec as invalid key bytes
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedKey);
        try {
            keyFactory.generatePublic(publicKeySpec);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message than expected: " + e.getMessage());
        }

    }

    /**
     * Verifies that {@code generatePrivate} rejects a {@link PKCS8EncodedKeySpec} that contains
     * public key bytes (symmetric counterpart to
     * {@link #generatePublicWithInvalidKeySpec(String)}).
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-KEM", "ML-KEM-512",
                "SLH-DSA", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f"})
    public void generatePrivateWithInvalidKeySpec(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // Pass public key bytes to PKCS8 spec - wrong content for a private key
        byte[] publicKeyBytes = generateKeyPair(algorithm).getPublic().getEncoded();
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(publicKeyBytes);
        try {
            keyFactory.generatePrivate(privateKeySpec);
            fail("Expected InvalidKeySpecException not thrown");
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message than expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that a generic PQC {@link KeyPairGenerator} accepts {@link NamedParameterSpec}
     * for any supported parameter set in its family.
     *
     * @param algParamSpecName the {@link NamedParameterSpec} name to initialize with
     * @throws Exception if initialization or key generation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    })
    public void genWithAlgParameterSpec(String algParamSpecName) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algParamSpecName) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        String family = BaseUtils.getFamilyName(algParamSpecName);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(family, getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(algParamSpecName);
        kpg.initialize(param);
        kpg.generateKeyPair();
    }

    /**
     * Verifies that an algorithm-specific {@link KeyPairGenerator} rejects
     * {@link NamedParameterSpec} values for sibling parameter sets.
     *
     * @param generatorAlg the algorithm used to obtain the KeyPairGenerator
     * @param mismatchedSpec the mismatched NamedParameterSpec name
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44, ML-DSA-65", "ML-DSA-44, ML-DSA-87", "ML-DSA-44, ML_DSA_65", "ML-DSA-44, ML_DSA_87",
        "ML-KEM-512, ML-KEM-768", "ML-KEM-512, ML-KEM-1024", "ML-KEM-512, ML_KEM_768", "ML-KEM-512, ML_KEM_1024",
        "ML-KEM-768, ML-KEM-512", "ML-KEM-1024, ML-KEM-512", "ML-KEM-768, ML_KEM_512", "ML-KEM-1024, ML_KEM_512",
        "SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128s, SLH_DSA_SHA2_128f",
        "SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s", "SLH-DSA-SHA2-128s, SLH_DSA_SHAKE-128s"
    })
    public void genWithAlgParameterSpecMismatchFailure(String generatorAlg, String mismatchedSpec) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(generatorAlg) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(generatorAlg, getProviderName());
        AlgorithmParameterSpec param = new NamedParameterSpec(mismatchedSpec);
        try {
            kpg.initialize(param);
            fail("Expected InvalidAlgorithmParameterException not thrown for " + generatorAlg + " / " + mismatchedSpec);
        } catch (InvalidAlgorithmParameterException e) {
            assertTrue(e.getMessage().equals("Algorithm in AlgorithmParameterSpec: " + mismatchedSpec +
                " must match the Algorithnm for this KeyPairGenerator: " + generatorAlg),
                "Different Message than expected: " + e.getMessage());
        }
    }

    @ParameterizedTest
    @CsvSource({
            "ML-KEM,             ML-KEM-768",
            "ML-KEM-512,         ML-KEM-512",
            "ML-KEM-768,         ML-KEM-768",
            "ML-KEM-1024,        ML-KEM-1024",
            "ML-DSA,             ML-DSA-65",
            "ML-DSA-44,          ML-DSA-44",
            "ML-DSA-65,          ML-DSA-65",
            "ML-DSA-87,          ML-DSA-87",
            "SLH-DSA,            SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128s,  SLH-DSA-SHA2-128s",
            "SLH-DSA-SHA2-128f,  SLH-DSA-SHA2-128f",
            "SLH-DSA-SHA2-192s,  SLH-DSA-SHA2-192s",
            "SLH-DSA-SHA2-192f,  SLH-DSA-SHA2-192f",
            "SLH-DSA-SHA2-256s,  SLH-DSA-SHA2-256s",
            "SLH-DSA-SHA2-256f,  SLH-DSA-SHA2-256f",
            "SLH-DSA-SHAKE-128s, SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHAKE-128f, SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s, SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHAKE-192f, SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s, SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHAKE-256f, SLH-DSA-SHAKE-256f"
    })
    public void testPQCKeyGetParams(String algorithm, String expectedParamSet)
            throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        KeyPairGenerator keyPairGenerator =
                KeyPairGenerator.getInstance(algorithm, getProviderName());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        assertTrue(keyPair.getPrivate().getParams() instanceof NamedParameterSpec);
        NamedParameterSpec privateParams =
                (NamedParameterSpec) keyPair.getPrivate().getParams();
        assertEquals(expectedParamSet, privateParams.getName());

        assertTrue(keyPair.getPublic().getParams() instanceof NamedParameterSpec);
        NamedParameterSpec publicParams =
                (NamedParameterSpec) keyPair.getPublic().getParams();
        assertEquals(expectedParamSet, publicParams.getName());
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
    /**
     * Tests that a generic KeyFactory (e.g. "ML-DSA" or "SLH-DSA") can decode public and private
     * keys originally generated with any specific parameter set within its family.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    })
    public void testGenericPQCKeyFactoryDecodesAllParamSets(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(paramSetName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        String family = BaseUtils.getFamilyName(paramSetName);

        // Generate a key pair using the specific parameter-set name
        KeyPair kp = generateKeyPair(paramSetName);
        byte[] x509Bytes  = kp.getPublic().getEncoded();
        byte[] pkcs8Bytes = kp.getPrivate().getEncoded();

        // Obtain a generic KeyFactory (family name, not param-set)
        KeyFactory genericKF = KeyFactory.getInstance(family, getProviderName());

        // Public key decode via generic KF must succeed for all param sets
        PublicKey pub;
        try {
            pub = genericKF.generatePublic(new X509EncodedKeySpec(x509Bytes));
        } catch (InvalidKeySpecException e) {
            fail("Generic " + family + " KeyFactory failed to decode " + paramSetName
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
            fail("Generic " + family + " KeyFactory failed to decode " + paramSetName
                    + " private key: " + e.getMessage());
            return;
        }
        assertArrayEquals(pkcs8Bytes, priv.getEncoded(),
                "Re-encoded private key bytes differ for " + paramSetName);
    }

    /**
     * Tests that key.getAlgorithm() returns the family name for keys
     * generated with any parameter set.
     */
    @ParameterizedTest
    @CsvSource({
        // ML-DSA canonical and aliases
        "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
        "MLDSA44", "MLDSA65", "MLDSA87",
        "ml-dsa-44", "ml-dsa-65", "ml-dsa-87",
        "Ml-Dsa-44", "Ml-Dsa-65", "Ml-Dsa-87",
        "ml_dsa_44", "ml_dsa_65", "ml_dsa_87",
        "mldsa44", "mldsa65", "mldsa87",
        "MlDsa44", "MlDsa65", "MlDsa87",
        // ML-KEM canonical and aliases
        "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
        "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
        "MLKEM512", "MLKEM768", "MLKEM1024",
        "ml-kem-512", "ml-kem-768", "ml-kem-1024",
        "Ml-Kem-512", "Ml-Kem-768", "Ml-Kem-1024",
        "ml_kem_512", "ml_kem_768", "ml_kem_1024",
        "mlkem512", "mlkem768", "mlkem1024",
        "MlKem512", "MlKem768", "MlKem1024",
        // SLH-DSA canonical and aliases
        "SLH-DSA", "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f",
        "SLH_DSA_SHA2_128s", "SLH_DSA_SHAKE_256f",
        "SLHDSASHA2128s", "SLHDSASHAKE256f",
        "slh-dsa-sha2-128s", "slh-dsa-shake-256f",
        "Slh-Dsa-Sha2-128s", "Slh-Dsa-Shake-256f",
        "slh_dsa_sha2_128s", "slh_dsa_shake_256f",
        "slhdsasha2128s", "slhdsashake256f",
        "SlhDsaSha2128s", "SlhDsaShake256f"
    })
    public void testPQCKeyAlgorithmReturnsFamilyName(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(paramSetName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        KeyPair kp = generateKeyPair(paramSetName);
        String expectedFamily = BaseUtils.getFamilyName(paramSetName);

        assertEquals(expectedFamily, kp.getPublic().getAlgorithm(),
                "getAlgorithm() on public key generated with " + paramSetName
                        + " should return family name \"" + expectedFamily + "\"");
        assertEquals(expectedFamily, kp.getPrivate().getAlgorithm(),
                "getAlgorithm() on private key generated with " + paramSetName
                        + " should return family name \"" + expectedFamily + "\"");
    }

    /**
     * Tests default parameter-set generation when KeyPairGenerator is obtained with a family name.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA, ML-DSA-65",
        "SLH-DSA, SLH-DSA-SHA2-128s"
    })
    public void testGenericKPGDefaultParamSet(String familyName, String expectedDefaultParamSet) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(familyName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        // Generate without calling initialize()
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(familyName, getProviderName());
        KeyPair defaultKp = kpg.generateKeyPair();

        // Generate an explicit key for comparison
        KeyPair explicitKp = generateKeyPair(expectedDefaultParamSet);

        assertEquals(explicitKp.getPublic().getEncoded().length,
                defaultKp.getPublic().getEncoded().length,
                "Default " + familyName + " public key length should equal " + expectedDefaultParamSet + " public key length");
        assertEquals(explicitKp.getPrivate().getEncoded().length,
                defaultKp.getPrivate().getEncoded().length,
                "Default " + familyName + " private key length should equal " + expectedDefaultParamSet + " private key length");

        // The family-name KF must accept the default key
        KeyFactory genericKF  = KeyFactory.getInstance(familyName, getProviderName());
        KeyFactory specificKF = KeyFactory.getInstance(expectedDefaultParamSet, getProviderName());

        // Round-trip through generic KF
        PublicKey  pubRound  = genericKF.generatePublic(
                new X509EncodedKeySpec(defaultKp.getPublic().getEncoded()));
        PrivateKey privRound = genericKF.generatePrivate(
                new PKCS8EncodedKeySpec(defaultKp.getPrivate().getEncoded()));

        assertArrayEquals(defaultKp.getPublic().getEncoded(), pubRound.getEncoded(),
                "Generic " + familyName + " KF: re-encoded public key bytes should be identical");
        assertArrayEquals(defaultKp.getPrivate().getEncoded(), privRound.getEncoded(),
                "Generic " + familyName + " KF: re-encoded private key bytes should be identical");

        // The specific KF must also accept the default key
        try {
            specificKF.generatePublic(
                    new X509EncodedKeySpec(defaultKp.getPublic().getEncoded()));
            specificKF.generatePrivate(
                    new PKCS8EncodedKeySpec(defaultKp.getPrivate().getEncoded()));
        } catch (Exception e) {
            fail(expectedDefaultParamSet + " specific KeyFactory rejected default " + familyName + " key: " + e.getMessage());
        }
    }

    /**
     * Tests that a generic KeyFactory can translateKey() for keys
     * from all parameter sets in its family.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    })
    public void testGenericPQCKeyFactoryTranslateKey(String paramSetName)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(paramSetName) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        String family = BaseUtils.getFamilyName(paramSetName);
        KeyPair kp = generateKeyPair(paramSetName);
        KeyFactory genericKF = KeyFactory.getInstance(family, getProviderName());

        try {
            PublicKey pub = (PublicKey) genericKF.translateKey(kp.getPublic());
            assertArrayEquals(kp.getPublic().getEncoded(), pub.getEncoded(),
                    "translateKey public key bytes differ for " + paramSetName);
        } catch (InvalidKeyException e) {
            fail("Generic " + family + " KeyFactory.translateKey() failed for "
                    + paramSetName + " public key: " + e.getMessage());
        }

        try {
            PrivateKey priv = (PrivateKey) genericKF.translateKey(kp.getPrivate());
            assertArrayEquals(kp.getPrivate().getEncoded(), priv.getEncoded(),
                    "translateKey private key bytes differ for " + paramSetName);
        } catch (InvalidKeyException e) {
            fail("Generic " + family + " KeyFactory.translateKey() failed for "
                    + paramSetName + " private key: " + e.getMessage());
        }
    }

    /**
     * Tests that a param-set-specific KeyFactory rejects a key that belongs
     * to a different parameter set within the same family.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44, ML-DSA-65", "ML-DSA-44, ML-DSA-87",
        "ML-DSA-65, ML-DSA-44", "ML-DSA-65, ML-DSA-87",
        "ML-DSA-87, ML-DSA-44", "ML-DSA-87, ML-DSA-65",
        "SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-128s, SLH-DSA-SHAKE-128s"
    })
    public void testSpecificPQCKeyFactoryRejectsWrongParamSet(
            String kfParamSet, String keyParamSet) throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(kfParamSet) && !BaseUtils.isOpenSSLProvider(getProviderName()));

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

        KeyFactory openjceplusKeyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        byte[] rfcPrivateKeyEncoded = decodePEM(privateKeyPem);

        // Both backends reject seed-only private keys. The check is performed in
        // PQCPrivateKey before any native call is made, so the error message is
        // identical regardless of which backend is active.
        try {
            openjceplusKeyFactory.generatePrivate(new PKCS8EncodedKeySpec(rfcPrivateKeyEncoded));
            fail("Expected InvalidKeySpecException for seed-only private key.");
        } catch (InvalidKeySpecException e) {
            assertEquals("Only expanded keys are supported by OpenJCEPlus",
                    e.getCause().getMessage());
        }
    }

    /**
     * Verifies the {@code getKeySpec} round-trip for public keys: a generated public key encoded
     * into an {@link X509EncodedKeySpec} must produce bytes identical to the original encoding.
     * Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if key generation or spec extraction fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f",
                "SLH_DSA_SHA2_128s", "SLH_DSA_SHAKE_256f"})
    public void testGetKeySpecPublicRoundTrip(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey publicKey = generateKeyPair(algorithm).getPublic();

        X509EncodedKeySpec spec = keyFactory.getKeySpec(publicKey, X509EncodedKeySpec.class);
        assertArrayEquals(publicKey.getEncoded(), spec.getEncoded(),
                "X509EncodedKeySpec bytes do not match original public key - " + algorithm);
    }

    /**
     * Verifies the {@code getKeySpec} round-trip for private keys: a generated private key encoded
     * into a {@link PKCS8EncodedKeySpec} must produce bytes identical to the original encoding.
     * Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if key generation or spec extraction fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f",
                "SLH_DSA_SHA2_128s", "SLH_DSA_SHAKE_256f"})
    public void testGetKeySpecPrivateRoundTrip(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PrivateKey privateKey = generateKeyPair(algorithm).getPrivate();

        PKCS8EncodedKeySpec spec = keyFactory.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
        assertArrayEquals(privateKey.getEncoded(), spec.getEncoded(),
                "PKCS8EncodedKeySpec bytes do not match original private key - " + algorithm);
    }

    /**
     * Verifies that {@code getKeySpec} throws {@link InvalidKeySpecException} when a
     * {@link PKCS8EncodedKeySpec} is requested for a public key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44", "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128s"})
    public void testGetKeySpecPublicWithWrongSpecType(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey publicKey = generateKeyPair(algorithm).getPublic();

        try {
            keyFactory.getKeySpec(publicKey, PKCS8EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException for PKCS8EncodedKeySpec on public key - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().equals("Inappropriate key specification"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code getKeySpec} throws {@link InvalidKeySpecException} when an
     * {@link X509EncodedKeySpec} is requested for a private key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44", "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128s"})
    public void testGetKeySpecPrivateWithWrongSpecType(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        PrivateKey privateKey = generateKeyPair(algorithm).getPrivate();

        try {
            keyFactory.getKeySpec(privateKey, X509EncodedKeySpec.class);
            fail("Expected InvalidKeySpecException for X509EncodedKeySpec on private key - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().equals("Inappropriate key specification"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code generatePublic} throws {@link InvalidKeySpecException} when passed a
     * {@link PKCS8EncodedKeySpec}, which is the wrong spec type for a public key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-KEM-768", "ML_KEM_768",
                "ML-DSA-44", "ML_DSA_44", "ML-DSA-65", "ML_DSA_65",
                "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128s"})
    public void generatePublicWithUnsupportedKeySpec(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // PKCS8EncodedKeySpec is the wrong spec type for generatePublic; must be rejected
        PKCS8EncodedKeySpec unsupportedSpec = new PKCS8EncodedKeySpec(new byte[]{0x01, 0x02});
        try {
            keyFactory.generatePublic(unsupportedSpec);
            fail("Expected InvalidKeySpecException for PKCS8EncodedKeySpec on generatePublic - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code generatePrivate} throws {@link InvalidKeySpecException} when passed an
     * {@link X509EncodedKeySpec}, which is the wrong spec type for a private key.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-KEM-768", "ML_KEM_768",
                "ML-DSA-44", "ML_DSA_44", "ML-DSA-65", "ML_DSA_65",
                "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128s"})
    public void generatePrivateWithUnsupportedKeySpec(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());

        // X509EncodedKeySpec is the wrong spec type for generatePrivate; must be rejected
        X509EncodedKeySpec unsupportedSpec = new X509EncodedKeySpec(new byte[]{0x01, 0x02});
        try {
            keyFactory.generatePrivate(unsupportedSpec);
            fail("Expected InvalidKeySpecException for X509EncodedKeySpec on generatePrivate - "
                    + algorithm);
        } catch (InvalidKeySpecException e) {
            assertTrue(e.getMessage().startsWith("Inappropriate key specification:"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code translateKey(null)} throws {@link InvalidKeyException} for both
     * '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML_KEM_512", "ML-DSA-44", "ML_DSA_44", "SLH-DSA-SHA2-128s", "SLH_DSA_SHA2_128s"})
    public void testTranslateKeyNull(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        try {
            keyFactory.translateKey(null);
            fail("Expected InvalidKeyException for null key on " + algorithm);
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().equals("Key must not be null"), "Different Message then expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that {@code translateKey} returns the identical object reference when the key
     * already originates from this provider. Covers both '-' and '_' algorithm name forms.
     *
     * @param algorithm the algorithm name to test
     * @throws Exception if translation fails unexpectedly
     */
    @ParameterizedTest
    @CsvSource({"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
                "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024",
                "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                "ML_DSA_44", "ML_DSA_65", "ML_DSA_87",
                "SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-256f",
                "SLH_DSA_SHA2_128s", "SLH_DSA_SHAKE_256f"})
    public void testTranslateKeyIdentity(String algorithm) throws Exception {
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm, getProviderName());
        KeyPair keyPair = generateKeyPair(algorithm);

        PublicKey pub = keyPair.getPublic();
        PrivateKey priv = keyPair.getPrivate();

        assertSame(pub, keyFactory.translateKey(pub),
                "translateKey should return the same PQCPublicKey object - " + algorithm);
        assertSame(priv, keyFactory.translateKey(priv),
                "translateKey should return the same PQCPrivateKey object - " + algorithm);
    }

    /**
     * Verifies that a {@link KeyFactory} for one PQC family (e.g. ML-KEM) rejects a key
     * belonging to a different family (e.g. ML-DSA), and vice versa.
     *
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512, ML-DSA-44",
        "ML-DSA-44, ML-KEM-512",
        "SLH-DSA-SHA2-128s, ML-DSA-44",
        "ML-DSA-44, SLH-DSA-SHA2-128s"
    })
    public void testTranslateKeyCrossFamilyRejection(String factoryAlg, String keyAlg) throws Exception {
        assumeFalse((BaseUtils.isSLHDSA(factoryAlg) || BaseUtils.isSLHDSA(keyAlg)) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory kf = KeyFactory.getInstance(factoryAlg, getProviderName());
        PrivateKey key = generateKeyPair(keyAlg).getPrivate();
        try {
            kf.translateKey(key);
            fail("Expected InvalidKeyException when translating " + keyAlg + " key with " + factoryAlg + " factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().startsWith("Expected a " + factoryAlg + " key, but got " + keyAlg),
                    "Different Message than expected: " + e.getMessage());
        }
    }

    /**
     * Verifies that a {@link KeyFactory} for a specific parameter set (e.g. ML-KEM-512) rejects
     * a key from a sibling parameter set within the same family (e.g. ML-KEM-768, ML-DSA-87, or SLH-DSA-SHA2-128f).
     *
     * @throws Exception if an unexpected error occurs
     */
    @ParameterizedTest
    @CsvSource({
        "ML-KEM-512, ML-KEM-768",
        "ML-DSA-44, ML-DSA-87",
        "SLH-DSA-SHA2-128s, SLH-DSA-SHA2-128f"
    })
    public void testTranslateKeySiblingRejection(String factoryAlg, String keyAlg) throws Exception {
        assumeFalse((BaseUtils.isSLHDSA(factoryAlg) || BaseUtils.isSLHDSA(keyAlg)) && !BaseUtils.isOpenSSLProvider(getProviderName()));
        KeyFactory kf = KeyFactory.getInstance(factoryAlg, getProviderName());
        PublicKey key = generateKeyPair(keyAlg).getPublic();
        try {
            kf.translateKey(key);
            fail("Expected InvalidKeyException when translating " + keyAlg + " key with " + factoryAlg + " factory");
        } catch (InvalidKeyException e) {
            assertTrue(e.getMessage().startsWith("Expected a " + factoryAlg + " key, but got " + keyAlg),
                    "Different Message than expected: " + e.getMessage());
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
     * <p>The OID position is derived dynamically from the outer SEQUENCE length
     * encoding: small keys (e.g. SLH-DSA, 32-byte public key) use a 2-byte
     * short-form header, while large keys (ML-KEM, ML-DSA) use a 4-byte long-form
     * header.  Both the X.509 SubjectPublicKeyInfo and PKCS#8 OneAsymmetricKey
     * encodings are checked to ensure {@link com.ibm.crypto.plus.provider.PQCKnownOIDs}
     * and {@link com.ibm.crypto.plus.provider.PQCAlgorithmId} agree with the standard.
     *
     * <p>OID values are from NIST FIPS 203/204/205:
     * <ul>
     *   <li>ML-KEM-512:  2.16.840.1.101.3.4.4.1  -> 6086480165030404 01</li>
     *   <li>ML-KEM-768:  2.16.840.1.101.3.4.4.2  -> 6086480165030404 02</li>
     *   <li>ML-KEM-1024: 2.16.840.1.101.3.4.4.3  -> 6086480165030404 03</li>
     *   <li>ML-DSA-44:   2.16.840.1.101.3.4.3.17 -> 6086480165030403 11</li>
     *   <li>ML-DSA-65:   2.16.840.1.101.3.4.3.18 -> 6086480165030403 12</li>
     *   <li>ML-DSA-87:   2.16.840.1.101.3.4.3.19 -> 6086480165030403 13</li>
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
        "ML-DSA,               608648016503040312",
        "SLH-DSA-SHA2-128s,    608648016503040314",
        "SLH-DSA-SHA2-128f,    608648016503040315",
        "SLH-DSA-SHA2-192s,    608648016503040316",
        "SLH-DSA-SHA2-192f,    608648016503040317",
        "SLH-DSA-SHA2-256s,    608648016503040318",
        "SLH-DSA-SHA2-256f,    608648016503040319",
        "SLH-DSA-SHAKE-128s,   60864801650304031a",
        "SLH-DSA-SHAKE-128f,   60864801650304031b",
        "SLH-DSA-SHAKE-192s,   60864801650304031c",
        "SLH-DSA-SHAKE-192f,   60864801650304031d",
        "SLH-DSA-SHAKE-256s,   60864801650304031e",
        "SLH-DSA-SHAKE-256f,   60864801650304031f",
        // Generic SLH-DSA name defaults to SLH-DSA-SHA2-128s (OID 2.16.840.1.101.3.4.3.20)
        "SLH-DSA,              608648016503040314"
    })
    public void testEncodedKeyContainsCorrectOID(String algorithm, String expectedOidHex)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(algorithm) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        // Strip any whitespace introduced by CsvSource padding
        expectedOidHex = expectedOidHex.strip();

        KeyPair kp = generateKeyPair(algorithm);

        // --- Public key (X.509 SubjectPublicKeyInfo) ---
        // Structure: SEQUENCE { SEQUENCE { OID, ... }, BIT STRING }
        // The outer SEQUENCE header is 2 bytes for short-form (small keys like SLH-DSA)
        // or 4 bytes for long-form (large keys like ML-KEM/ML-DSA).  Skip it dynamically.
        byte[] x509 = kp.getPublic().getEncoded();
        // byte 0 = 0x30 (SEQUENCE tag); byte 1 = length byte
        // if bit 7 of byte 1 is set it is long-form: the low 7 bits give the number of
        // subsequent length bytes.  For our keys only 1 or 2 extra length bytes are used.
        int x509HeaderLen = (x509[1] & 0x80) != 0 ? 2 + (x509[1] & 0x7f) : 2;
        // after outer header: inner AlgId SEQUENCE (30 0b), then OID tag+len (06 09)
        int x509OidTagOffset = x509HeaderLen + 2; // skip inner SEQUENCE tag + length byte
        assertEquals("0609", BaseUtils.bytesToHex(new byte[]{x509[x509OidTagOffset], x509[x509OidTagOffset + 1]}),
                "X.509 encoding for " + algorithm + " should contain OID tag 06, length 09");
        String actualPublicOid = BaseUtils.bytesToHex(java.util.Arrays.copyOfRange(
                x509, x509OidTagOffset + 2, x509OidTagOffset + 11)); // 9 OID bytes
        assertEquals(expectedOidHex, actualPublicOid,
                "X.509 OID mismatch for " + algorithm);

        // --- Private key (PKCS#8 OneAsymmetricKey) ---
        // Structure: SEQUENCE { INTEGER (version=0), SEQUENCE { OID, ... }, OCTET STRING }
        // Same variable-length outer SEQUENCE header, then 02 01 00 (3 bytes), then AlgId.
        byte[] pkcs8 = kp.getPrivate().getEncoded();
        int pkcs8HeaderLen = (pkcs8[1] & 0x80) != 0 ? 2 + (pkcs8[1] & 0x7f) : 2;
        // after outer header: version INTEGER (02 01 00 = 3 bytes), inner AlgId SEQUENCE (30 0b)
        int pkcs8OidTagOffset = pkcs8HeaderLen + 3 + 2; // skip version + inner SEQUENCE tag+len
        assertEquals("0609", BaseUtils.bytesToHex(new byte[]{pkcs8[pkcs8OidTagOffset], pkcs8[pkcs8OidTagOffset + 1]}),
                "PKCS#8 encoding for " + algorithm + " should contain OID tag 06, length 09");
        String actualPrivateOid = BaseUtils.bytesToHex(java.util.Arrays.copyOfRange(
                pkcs8, pkcs8OidTagOffset + 2, pkcs8OidTagOffset + 11)); // 9 OID bytes
        assertEquals(expectedOidHex, actualPrivateOid,
                "PKCS#8 OID mismatch for " + algorithm);

        // Verify the key round-trips correctly through KeyFactory using the embedded OID
        KeyFactory kf = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey  pub2  = kf.generatePublic(new X509EncodedKeySpec(x509));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        assertArrayEquals(x509,  pub2.getEncoded(),  "Public key round-trip failed for "  + algorithm);
        assertArrayEquals(pkcs8, priv2.getEncoded(), "Private key round-trip failed for " + algorithm);

        // Confirm getAlgorithm() returns the expected family name
        String expectedFamily = BaseUtils.getFamilyName(algorithm);
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
     *   <li>Underscore name  - e.g. {@code ML_KEM_512}</li>
     *   <li>Compact name     - e.g. {@code MLKEM512}</li>
     *   <li>{@code OID.xxx}  - e.g. {@code OID.2.16.840.1.101.3.4.4.1}</li>
     *   <li>Bare OID string  - e.g. {@code 2.16.840.1.101.3.4.4.1}</li>
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
        assumeFalse(BaseUtils.isSLHDSA(canonicalParamSet) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        // Generate with the canonical param-set name so we have a known key
        KeyPair kp = generateKeyPair(canonicalParamSet);
        byte[] x509bytes  = kp.getPublic().getEncoded();
        byte[] pkcs8bytes = kp.getPrivate().getEncoded();

        // Obtain a KeyFactory through the alias name - this is what we are testing
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
            Arguments.of("oid.2.16.840.1.101.3.4.3.19",  "ML-DSA-87",   "ML-DSA"),
            // ---- SLH-DSA-SHA2-128s aliases ----
            Arguments.of("SLH_DSA_SHA2_128s",             "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("SLHDSASHA2128s",               "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.20",  "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("2.16.840.1.101.3.4.3.20",      "SLH-DSA-SHA2-128s", "SLH-DSA"),
            // mixed-case SLH-DSA-SHA2-128s
            Arguments.of("slh-dsa-sha2-128s",             "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("Slh-Dsa-Sha2-128s",             "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("slh_dsa_sha2_128s",             "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("slhdsasha2128s",               "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("SlhDsaSha2128s",               "SLH-DSA-SHA2-128s", "SLH-DSA"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.20",  "SLH-DSA-SHA2-128s", "SLH-DSA"),
            // ---- SLH-DSA-SHAKE-256f aliases ----
            Arguments.of("SLH_DSA_SHAKE_256f",            "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("SLHDSASHAKE256f",              "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.31",  "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("2.16.840.1.101.3.4.3.31",      "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            // mixed-case SLH-DSA-SHAKE-256f
            Arguments.of("slh-dsa-shake-256f",            "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("Slh-Dsa-Shake-256f",            "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("slh_dsa_shake_256f",            "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("slhdsashake256f",              "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("SlhDsaShake256f",              "SLH-DSA-SHAKE-256f", "SLH-DSA"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.31",  "SLH-DSA-SHAKE-256f", "SLH-DSA")
        );
    }

    /**
     * Verifies that all registered OID alias forms for the signature
     * services resolve to the correct param-set implementation and can sign and
     * verify a message.
     *
     * <p>Parameters: alias, canonical param-set name used to generate the signing key.
     */
    @ParameterizedTest
    @MethodSource("signatureOidAliasArgs")
    public void testPQCSignatureOidAliasWorks(String alias, String canonicalParamSet)
            throws Exception {
        assumeFalse("OpenJCEPlusFIPS".equals(getProviderName()));
        assumeFalse(BaseUtils.isSLHDSA(canonicalParamSet) && !BaseUtils.isOpenSSLProvider(getProviderName()));

        byte[] msg = "test message for OID alias signature".getBytes();

        KeyPair kp = generateKeyPair(canonicalParamSet);

        // Sign using the alias name - verifies getInstance() resolves correctly
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
            Arguments.of("oid.2.16.840.1.101.3.4.3.19", "ML-DSA-87"),
            // ---- SLH-DSA-SHA2-128s aliases ----
            Arguments.of("SLH_DSA_SHA2_128s",            "SLH-DSA-SHA2-128s"),
            Arguments.of("SLHDSASHA2128s",              "SLH-DSA-SHA2-128s"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),
            Arguments.of("2.16.840.1.101.3.4.3.20",     "SLH-DSA-SHA2-128s"),
            // mixed-case SLH-DSA-SHA2-128s
            Arguments.of("slh-dsa-sha2-128s",            "SLH-DSA-SHA2-128s"),
            Arguments.of("Slh-Dsa-Sha2-128s",            "SLH-DSA-SHA2-128s"),
            Arguments.of("slh_dsa_sha2_128s",            "SLH-DSA-SHA2-128s"),
            Arguments.of("slhdsasha2128s",              "SLH-DSA-SHA2-128s"),
            Arguments.of("SlhDsaSha2128s",              "SLH-DSA-SHA2-128s"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.20", "SLH-DSA-SHA2-128s"),
            // ---- SLH-DSA-SHAKE-256f aliases ----
            Arguments.of("SLH_DSA_SHAKE_256f",           "SLH-DSA-SHAKE-256f"),
            Arguments.of("SLHDSASHAKE256f",             "SLH-DSA-SHAKE-256f"),
            Arguments.of("OID.2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f"),
            Arguments.of("2.16.840.1.101.3.4.3.31",     "SLH-DSA-SHAKE-256f"),
            // mixed-case SLH-DSA-SHAKE-256f
            Arguments.of("slh-dsa-shake-256f",           "SLH-DSA-SHAKE-256f"),
            Arguments.of("Slh-Dsa-Shake-256f",           "SLH-DSA-SHAKE-256f"),
            Arguments.of("slh_dsa_shake_256f",           "SLH-DSA-SHAKE-256f"),
            Arguments.of("slhdsashake256f",             "SLH-DSA-SHAKE-256f"),
            Arguments.of("SlhDsaShake256f",             "SLH-DSA-SHAKE-256f"),
            Arguments.of("oid.2.16.840.1.101.3.4.3.31", "SLH-DSA-SHAKE-256f")
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
        PublicKey pub = pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv = pqcKeyFactory.generatePrivate(pkcs8Spec);

        assertArrayEquals(pub.getEncoded(), pqcKeyPair.getPublic().getEncoded(),
                "Public key does not match generated public key - " + Algorithm);
        assertArrayEquals(priv.getEncoded(), pqcKeyPair.getPrivate().getEncoded(),
                "Private key does not match generated private key - " + Algorithm);

    }
}
