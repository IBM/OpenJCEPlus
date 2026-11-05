/*
 * Copyright IBM Corp. 2023, 2026
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
import java.security.ProviderException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusWithSunRsaSignInteropProvider")
public class TestRSAPSSInterop2 extends BaseTestInterop {

    private static final int[] KEY_SIZES = {512, 1024, 2048, 3072, 4096, 5120};
    // SunRsaSign raises InvalidKeyException for SHA-384/SHA-512 on 512-bit keys.
    private static final int SUNRSASIGN_MIN_KEY_SIZE = 1024;
    // FIPS mode only accepts 2048, 3072, and 4096-bit RSA keys.
    private static final int FIPS_MIN_KEY_SIZE = 2048;
    private static final int FIPS_MAX_KEY_SIZE = 4096;

    private static final byte[] DATA_SHORT = "a".getBytes();
    private static final byte[] DATA_MEDIUM =
            "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    .getBytes();
    private static final byte[] DATA_LONG =
            "this is text to test the RSAPSS Signature xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    .getBytes();

    private static final byte[][] ALL_DATA = {DATA_SHORT, DATA_MEDIUM, DATA_LONG};

    final String signingProvidersSignatureAlgorithmName = "RSASSA-PSS";
    final String verifyingProvidersSignatureAlgorithmName = "RSASSA-PSS";

    // Per-provider (signing) key pair cache
    private static final Map<String, KeyPair[]> KEY_PAIR_CACHE = new HashMap<>();

    @Parameter(0)
    TestProvider provider;

    @Parameter(1)
    TestProvider interopProvider;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
        setAndInsertInteropProvider(interopProvider);
    }

    private static KeyPair[] getKeyPairs(String signerName) throws Exception {
        int minKeySize = 512;
        int maxKeySize = 5120;
        if (signerName.equalsIgnoreCase("SunRsaSign")) {
            minKeySize = SUNRSASIGN_MIN_KEY_SIZE;
        } else if (signerName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            minKeySize = FIPS_MIN_KEY_SIZE;
            maxKeySize = FIPS_MAX_KEY_SIZE;
        }
        return getKeyPairs(signerName, minKeySize, maxKeySize);
    }

    private static synchronized KeyPair[] getKeyPairs(String providerName, int minSize,
            int maxSize) throws Exception {
        KeyPair[] pairs = KEY_PAIR_CACHE.get(providerName);
        if (pairs == null) {
            pairs = new KeyPair[KEY_SIZES.length];
            for (int i = 0; i < KEY_SIZES.length; i++) {
                if (KEY_SIZES[i] < minSize || KEY_SIZES[i] > maxSize) {
                    continue;
                }
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", providerName);
                kpg.initialize(KEY_SIZES[i], null);
                pairs[i] = kpg.generateKeyPair();
            }
            KEY_PAIR_CACHE.put(providerName, pairs);
        }
        return pairs;
    }

    // -------------------------------------------------------------------------
    // PSS parameter source methods
    // -------------------------------------------------------------------------

    static Stream<Arguments> matchingPssParams() {
        return Stream.of(
            // mdName, mgf, saltLen, trailerField, keyTooShortThreshold (-1 = none)
            Arguments.of("SHA1",   MGF1ParameterSpec.SHA1,   20, 1, -1),
            Arguments.of("SHA224", MGF1ParameterSpec.SHA224, 20, 1, -1),
            Arguments.of("SHA256", MGF1ParameterSpec.SHA256, 20, 1, -1),
            Arguments.of("SHA384", MGF1ParameterSpec.SHA384, 20, 1, 0),
            Arguments.of("SHA512", MGF1ParameterSpec.SHA512, 20, 1, 0)
        );
    }

    static Stream<Arguments> mismatchedPssParams() {
        return Stream.of(
            // Group 1: rotating next-digest mismatch
            Arguments.of("SHA1",   MGF1ParameterSpec.SHA224),
            Arguments.of("SHA224", MGF1ParameterSpec.SHA256),
            Arguments.of("SHA256", MGF1ParameterSpec.SHA384),
            Arguments.of("SHA384", MGF1ParameterSpec.SHA512),
            Arguments.of("SHA512", MGF1ParameterSpec.SHA1),
            // Group 2: SHA-1 alias paired with four mismatched MGF digests
            Arguments.of("SHA-1",  MGF1ParameterSpec.SHA224),
            Arguments.of("SHA-1",  MGF1ParameterSpec.SHA256),
            Arguments.of("SHA-1",  MGF1ParameterSpec.SHA384),
            Arguments.of("SHA-1",  MGF1ParameterSpec.SHA512)
        );
    }

    static Stream<Arguments> sha1AliasPssParams() {
        return Stream.of(
            Arguments.of("SHA-1", MGF1ParameterSpec.SHA1, 20, 1, -1)
        );
    }

    static Stream<Arguments> varyingSaltPssParams() {
        return Stream.of(
            Arguments.of("SHA1",   MGF1ParameterSpec.SHA1,   40,  1, -1),
            Arguments.of("SHA224", MGF1ParameterSpec.SHA224, 60,  1, 0),
            Arguments.of("SHA256", MGF1ParameterSpec.SHA256, 80,  1, 0),
            Arguments.of("SHA384", MGF1ParameterSpec.SHA384, 100, 1, 1),
            Arguments.of("SHA512", MGF1ParameterSpec.SHA512, 200, 1, 2)
        );
    }

    static Stream<Arguments> sha1PssParams() {
        return Stream.of(
            // mdName, mgf
            Arguments.of("SHA1",  MGF1ParameterSpec.SHA1),
            Arguments.of("SHA-1", MGF1ParameterSpec.SHA1)
        );
    }

    // -------------------------------------------------------------------------
    // Test methods
    // -------------------------------------------------------------------------

    @ParameterizedTest
    @MethodSource("matchingPssParams")
    public void testRSAPSSMatching(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold);
    }

    @ParameterizedTest
    @MethodSource("sha1AliasPssParams")
    public void testRSAPSSSha1Alias(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold);
    }

    @ParameterizedTest
    @MethodSource("varyingSaltPssParams")
    public void testRSAPSSVaryingSalt(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold);
    }

    @ParameterizedTest
    @MethodSource("mismatchedPssParams")
    public void testRSAPSSMismatch(String mdName, MGF1ParameterSpec mgf) throws Exception {
        runPssMismatch(mdName, mgf);
    }

    @ParameterizedTest
    @MethodSource("sha1PssParams")
    public void testRSAPSSSha1RejectedInFips(String mdName, MGF1ParameterSpec mgf)
            throws Exception {
        runSha1RejectedInFips(mdName, mgf);
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    private boolean isFipsInvolved() {
        return getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS")
                || getInteropProviderName().equalsIgnoreCase("OpenJCEPlusFIPS");
    }

    private static boolean isSha1(String mdName) {
        return mdName.equalsIgnoreCase("SHA1") || mdName.equalsIgnoreCase("SHA-1")
                || mdName.equalsIgnoreCase("SHA");
    }

    private void runPssSignVerify(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        assumeFalse(isSha1(mdName) && isFipsInvolved(),
                "SHA-1 is not approved in FIPS mode; see testRSAPSSSha1RejectedInFips");

        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold,
                getProviderName(), getInteropProviderName());
        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold,
                getInteropProviderName(), getProviderName());
    }

    private void runPssSignVerify(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold,
            String signerName, String verifierName) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(mdName, "MGF1", mgf, saltLen, trailerField);
        KeyPair[] rsaKeyPairs = getKeyPairs(signerName);

        for (int ii = 0; ii < KEY_SIZES.length; ii++) {
            if (rsaKeyPairs[ii] == null) {
                continue;
            }
            KeyPair kp = rsaKeyPairs[ii];
            for (int jj = 0; jj < ALL_DATA.length; jj++) {
                if (ii <= keyTooShortThreshold) {
                    try {
                        doSignature(ALL_DATA[jj], kp, spec, signerName, verifierName);
                        fail("Expected InvalidKeyException for signer=" + signerName
                                + " verifier=" + verifierName
                                + " mdName=" + mdName
                                + " keySize=" + KEY_SIZES[ii]);
                    } catch (InvalidKeyException ex) {
                        if (ex.getMessage() == null
                                || ex.getMessage().indexOf("Key is too short") == -1) {
                            fail("Unexpected exception message for signer=" + signerName
                                    + " verifier=" + verifierName
                                    + " mdName=" + mdName
                                    + " keySize=" + KEY_SIZES[ii]
                                    + ": " + ex.getMessage());
                        }
                    }
                } else {
                    boolean result = doSignature(ALL_DATA[jj], kp, spec, signerName, verifierName);
                    assertTrue(result, "Signature verification failed: signer=" + signerName
                            + " verifier=" + verifierName
                            + " mdName=" + mdName + " keySize=" + KEY_SIZES[ii]);
                }
            }
        }
    }

    private void runPssMismatch(String mdName, MGF1ParameterSpec mgf) throws Exception {
        runPssMismatch(mdName, mgf, getProviderName(), getInteropProviderName());
        runPssMismatch(mdName, mgf, getInteropProviderName(), getProviderName());
    }

    private void runPssMismatch(String mdName, MGF1ParameterSpec mgf,
            String signerName, String verifierName) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(mdName, "MGF1", mgf, 20, 1);
        KeyPair[] rsaKeyPairs = getKeyPairs(signerName);

        for (int ii = 0; ii < KEY_SIZES.length; ii++) {
            if (rsaKeyPairs[ii] == null) {
                continue;
            }
            KeyPair kp = rsaKeyPairs[ii];
            for (int jj = 0; jj < ALL_DATA.length; jj++) {
                try {
                    doSignature(ALL_DATA[jj], kp, spec, signerName, verifierName);
                    fail("Expected InvalidAlgorithmParameterException for signer=" + signerName
                            + " verifier=" + verifierName
                            + " mdName=" + mdName
                            + " mgf=" + mgf.getDigestAlgorithm()
                            + " keySize=" + KEY_SIZES[ii]);
                } catch (InvalidAlgorithmParameterException ex) {
                    String message = ex.getMessage();
                    if (message == null || message.indexOf(
                            "The message digest within the PSSParameterSpec does not match"
                            + " the MGF message digest.") == -1) {
                        fail("Unexpected exception message for signer=" + signerName
                                + " verifier=" + verifierName
                                + " mdName=" + mdName
                                + " mgf=" + mgf.getDigestAlgorithm()
                                + " keySize=" + KEY_SIZES[ii]
                                + ": " + ex.getMessage());
                    }
                }
            }
        }
    }

    private void runSha1RejectedInFips(String mdName, MGF1ParameterSpec mgf) throws Exception {
        assumeTrue(isFipsInvolved(), "No FIPS provider in this signer/verifier pair");

        runSha1RejectedInFips(mdName, mgf, getProviderName(), getInteropProviderName());
        runSha1RejectedInFips(mdName, mgf, getInteropProviderName(), getProviderName());
    }

    private void runSha1RejectedInFips(String mdName, MGF1ParameterSpec mgf,
            String signerName, String verifierName) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(mdName, "MGF1", mgf, 20, 1);

        KeyPair firstKeyPair = null;
        for (KeyPair kp : getKeyPairs(signerName)) {
            if (kp != null) {
                firstKeyPair = kp;
                break;
            }
        }

        try {
            doSignature(ALL_DATA[0], firstKeyPair, spec, signerName, verifierName);
            fail("Expected exception: SHA-1 not approved for PSS in FIPS mode, signer="
                    + signerName + " verifier=" + verifierName);
        } catch (ProviderException ex) {
            // FIPS as signer: ProviderException("SHA1 not supported by FIPS.")
            assertTrue(ex.getMessage() != null
                    && ex.getMessage().contains("SHA1 not supported by FIPS"),
                    "Unexpected ProviderException message: " + ex.getMessage());
        } catch (InvalidAlgorithmParameterException ex) {
            // FIPS as verifier: InvalidAlgorithmParameterException (mismatch check path)
            assertTrue(ex.getMessage() != null && !ex.getMessage().isEmpty(),
                    "Unexpected empty InvalidAlgorithmParameterException message");
        }
    }

    private boolean doSignature(byte[] data, KeyPair keyPair, PSSParameterSpec pssSpec,
            String signerName, String verifierName) throws Exception {
        Signature sig = Signature.getInstance(signingProvidersSignatureAlgorithmName, signerName);
        sig.setParameter(pssSpec);
        sig.initSign(keyPair.getPrivate());
        sig.update(data);
        byte[] sigBytes = sig.sign();

        RSAPublicKey translatedPublicKey;
        if (signerName.equalsIgnoreCase(verifierName)) {
            translatedPublicKey = (RSAPublicKey) keyPair.getPublic();
        } else {
            KeyFactory kf = KeyFactory.getInstance("RSA", verifierName);
            translatedPublicKey = (RSAPublicKey) kf.translateKey(keyPair.getPublic());
        }

        sig = Signature.getInstance(verifyingProvidersSignatureAlgorithmName, verifierName);
        sig.setParameter(pssSpec);
        sig.initVerify(translatedPublicKey);
        sig.update(data);

        return sig.verify(sigBytes);
    }
}
