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

@Tag(Tags.OPENJCEPLUS_NAME)
@Tag(Tags.OPENJCEPLUS_FIPS_NAME)
@Tag(Tags.MULTITHREAD_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getRSAPSSInteropProviderPairs")
public class TestRSAPSSInterop2 extends BaseTestInterop {

    private static final int[] KEY_SIZES = {512, 1024, 2048, 3072, 4096, 5120};

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

    String signingProviderName = null;
    String verifyingProviderName = null;

    KeyPair[] rsaKeyPairs = new KeyPair[KEY_SIZES.length];
    int keyLoopStartIndex = 0;
    int keyLoopEndIndex = KEY_SIZES.length;

    @Parameter(0)
    TestProvider signingProvider;

    @Parameter(1)
    TestProvider verifyingProvider;

    String currentKeyProvider = null;

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(signingProvider);
        setAndInsertInteropProvider(verifyingProvider);

        signingProviderName = getProviderName();
        verifyingProviderName = getInteropProviderName();

        if (signingProviderName.equals(currentKeyProvider)) {
            return;
        }

        if (signingProviderName.equalsIgnoreCase("SunRsaSign")) {
            // SunRsaSign raises InvalidKeyException for SHA-384/SHA-512 on 512-bit keys.
            keyLoopStartIndex = 1;
            keyLoopEndIndex = KEY_SIZES.length;
        } else if (signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")) {
            // FIPS mode only accepts 2048, 3072, and 4096-bit RSA keys.
            keyLoopStartIndex = 2;
            keyLoopEndIndex = 5; // index 5 is 5120-bit, not accepted in FIPS mode
        } else {
            keyLoopStartIndex = 0;
            keyLoopEndIndex = KEY_SIZES.length;
        }

        for (int i = keyLoopStartIndex; i < keyLoopEndIndex; i++) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", signingProviderName);
            kpg.initialize(KEY_SIZES[i], null);
            rsaKeyPairs[i] = kpg.generateKeyPair();
        }
        currentKeyProvider = signingProviderName;
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

    static Stream<Arguments> trailerFieldPssParams() {
        return Stream.of(
            Arguments.of("SHA1",   MGF1ParameterSpec.SHA1,   20, 1, -1),
            Arguments.of("SHA224", MGF1ParameterSpec.SHA224, 20, 1, -1),
            Arguments.of("SHA256", MGF1ParameterSpec.SHA256, 20, 1, -1),
            Arguments.of("SHA384", MGF1ParameterSpec.SHA384, 20, 1, 0),
            Arguments.of("SHA512", MGF1ParameterSpec.SHA512, 20, 1, 0)
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
    @MethodSource("trailerFieldPssParams")
    public void testRSAPSSTrailerField(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        runPssSignVerify(mdName, mgf, saltLen, trailerField, keyTooShortThreshold);
    }

    @ParameterizedTest
    @MethodSource("mismatchedPssParams")
    public void testRSAPSSMismatch(String mdName, MGF1ParameterSpec mgf) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(mdName, "MGF1", mgf, 20, 1);

        for (int ii = keyLoopStartIndex; ii < keyLoopEndIndex; ii++) {
            KeyPair kp = rsaKeyPairs[ii];
            for (int jj = 0; jj < ALL_DATA.length; jj++) {
                try {
                    doSignature(ALL_DATA[jj], kp, spec);
                    fail("Expected InvalidAlgorithmParameterException for mdName=" + mdName
                            + " mgf=" + mgf.getDigestAlgorithm()
                            + " keySize=" + KEY_SIZES[ii]);
                } catch (InvalidAlgorithmParameterException ex) {
                    if (ex.getMessage().indexOf(
                            "The message digest within the PSSParameterSpec does not match"
                            + " the MGF message digest.") == -1) {
                        fail("Unexpected exception message for mdName=" + mdName
                                + " mgf=" + mgf.getDigestAlgorithm()
                                + " keySize=" + KEY_SIZES[ii]
                                + ": " + ex.getMessage());
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    private void runPssSignVerify(String mdName, MGF1ParameterSpec mgf,
            int saltLen, int trailerField, int keyTooShortThreshold) throws Exception {
        PSSParameterSpec spec = new PSSParameterSpec(mdName, "MGF1", mgf, saltLen, trailerField);

        boolean isSha1 = mdName.equalsIgnoreCase("SHA1") || mdName.equalsIgnoreCase("SHA-1")
                || mdName.equalsIgnoreCase("SHA");
        boolean fipsInvolved = signingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS")
                || verifyingProviderName.equalsIgnoreCase("OpenJCEPlusFIPS");

        if (isSha1 && fipsInvolved) {
            // SHA-1 is not approved in FIPS mode. Verify the provider actively rejects it.
            try {
                doSignature(ALL_DATA[0], rsaKeyPairs[keyLoopStartIndex], spec);
                fail("Expected exception: SHA-1 not approved for PSS in FIPS mode");
            } catch (ProviderException ex) {
                // FIPS as signer: ProviderException("SHA1 not supported by FIPS.")
                assertTrue(ex.getMessage().contains("SHA1 not supported by FIPS"),
                        "Unexpected ProviderException message: " + ex.getMessage());
            } catch (InvalidAlgorithmParameterException ex) {
                // FIPS as verifier: InvalidAlgorithmParameterException (mismatch check path)
                assertTrue(ex.getMessage() != null && !ex.getMessage().isEmpty(),
                        "Unexpected empty InvalidAlgorithmParameterException message");
            }
            return;
        }

        for (int ii = keyLoopStartIndex; ii < keyLoopEndIndex; ii++) {
            KeyPair kp = rsaKeyPairs[ii];
            if (kp == null) {
                fail("Key pair is null for " + signingProviderName
                        + " at key-size index " + ii + " (" + KEY_SIZES[ii] + " bits)");
            }
            for (int jj = 0; jj < ALL_DATA.length; jj++) {
                if (ii <= keyTooShortThreshold) {
                    try {
                        doSignature(ALL_DATA[jj], kp, spec);
                        fail("Expected InvalidKeyException for mdName=" + mdName
                                + " keySize=" + KEY_SIZES[ii]);
                    } catch (InvalidKeyException ex) {
                        if (ex.getMessage().indexOf("Key is too short") == -1) {
                            fail("Unexpected exception message for mdName=" + mdName
                                    + " keySize=" + KEY_SIZES[ii]
                                    + ": " + ex.getMessage());
                        }
                    }
                } else {
                    boolean result = doSignature(ALL_DATA[jj], kp, spec);
                    assertTrue(result, "Signature verification failed: signer=" + signingProviderName
                            + " verifier=" + verifyingProviderName
                            + " mdName=" + mdName + " keySize=" + KEY_SIZES[ii]);
                }
            }
        }
    }

    private boolean doSignature(byte[] data, KeyPair keyPair,
            PSSParameterSpec pssSpec) throws Exception {
        Signature sig = Signature.getInstance(signingProvidersSignatureAlgorithmName, signingProviderName);
        sig.setParameter(pssSpec);
        sig.initSign(keyPair.getPrivate());
        sig.update(data);
        byte[] sigBytes = sig.sign();

        RSAPublicKey translatedPublicKey;
        if (signingProviderName.equalsIgnoreCase(verifyingProviderName)) {
            translatedPublicKey = (RSAPublicKey) keyPair.getPublic();
        } else {
            KeyFactory kf = KeyFactory.getInstance("RSA", verifyingProviderName);
            translatedPublicKey = (RSAPublicKey) kf.translateKey(keyPair.getPublic());
        }

        sig = Signature.getInstance(verifyingProvidersSignatureAlgorithmName, verifyingProviderName);
        sig.setParameter(pssSpec);
        sig.initVerify(translatedPublicKey);
        sig.update(data);

        return sig.verify(sigBytes);
    }
}
