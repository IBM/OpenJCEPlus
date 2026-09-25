/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.tests;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.Parameter;
import org.junit.jupiter.params.ParameterizedClass;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for composite signature algorithms defined in
 * draft-ietf-lamps-pq-composite-sigs.
 *
 * <p>Covers: round-trip sign/verify, key encoding round-trip (PKCS#8 /
 * X.509), rejection of tampered signatures, and rejection of a wrong public
 * key.
 */
@Tag(Tags.OPENJCEPLUS_NAME)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ParameterizedClass
@MethodSource("ibm.jceplus.junit.tests.TestArguments#getOpenJCEPlusOnly")
public class TestCompositeSignature extends BaseTestSignature {

    @Parameter(0)
    TestProvider provider;

    static final byte[] origMsg =
            "Composite PQ signature test message".getBytes();

    @BeforeEach
    public void setUp() throws Exception {
        setAndInsertProvider(provider);
    }

    // -----------------------------------------------------------------------
    // Round-trip sign / verify
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA44-RSA2048-PKCS15-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-RSA3072-PSS-SHA512",
        "MLDSA65-RSA3072-PKCS15-SHA512",
        "MLDSA65-RSA4096-PSS-SHA512",
        "MLDSA65-RSA4096-PKCS15-SHA512",
        "MLDSA65-ECDSA-P256-SHA512",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P384-SHA512",
        "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448",
        "MLDSA87-RSA3072-PSS-SHA512",
        "MLDSA87-RSA4096-PSS-SHA512"
    })
    public void testSignVerify(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        doSignVerify(algorithm, origMsg, kp.getPrivate(), kp.getPublic());
    }

    // -----------------------------------------------------------------------
    // Key encoding round-trip (X.509 public / PKCS#8 private)
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA44-RSA2048-PKCS15-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-RSA3072-PSS-SHA512",
        "MLDSA65-RSA3072-PKCS15-SHA512",
        "MLDSA65-RSA4096-PSS-SHA512",
        "MLDSA65-RSA4096-PKCS15-SHA512",
        "MLDSA65-ECDSA-P256-SHA512",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P384-SHA512",
        "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448",
        "MLDSA87-RSA3072-PSS-SHA512",
        "MLDSA87-RSA4096-PSS-SHA512"
    })
    public void testKeyEncodingRoundTrip(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);

        byte[] pubEncoded = kp.getPublic().getEncoded();
        byte[] privEncoded = kp.getPrivate().getEncoded();

        KeyFactory kf = KeyFactory.getInstance(algorithm, getProviderName());
        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pubEncoded));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(privEncoded));

        doSignVerify(algorithm, origMsg, priv2, pub2);
    }

    // -----------------------------------------------------------------------
    // Tampered signature must not verify
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA44-RSA2048-PKCS15-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-RSA3072-PSS-SHA512",
        "MLDSA65-RSA3072-PKCS15-SHA512",
        "MLDSA65-RSA4096-PSS-SHA512",
        "MLDSA65-RSA4096-PKCS15-SHA512",
        "MLDSA65-ECDSA-P256-SHA512",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P384-SHA512",
        "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448",
        "MLDSA87-RSA3072-PSS-SHA512",
        "MLDSA87-RSA4096-PSS-SHA512"
    })
    public void testTamperedSignatureFails(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);

        Signature signing = Signature.getInstance(algorithm, getProviderName());
        signing.initSign(kp.getPrivate());
        signing.update(origMsg);
        byte[] sig = signing.sign();

        // Flip the last byte of the signature
        sig[sig.length - 1] ^= (byte) 0xFF;

        Signature verifying = Signature.getInstance(algorithm, getProviderName());
        verifying.initVerify(kp.getPublic());
        verifying.update(origMsg);

        assertFalse(verifying.verify(sig),
                "Tampered signature should not verify for " + algorithm);
    }

    // -----------------------------------------------------------------------
    // Wrong public key must not verify
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {
        "MLDSA44-RSA2048-PSS-SHA256",
        "MLDSA44-RSA2048-PKCS15-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA65-RSA3072-PSS-SHA512",
        "MLDSA65-RSA3072-PKCS15-SHA512",
        "MLDSA65-RSA4096-PSS-SHA512",
        "MLDSA65-RSA4096-PKCS15-SHA512",
        "MLDSA65-ECDSA-P256-SHA512",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-ECDSA-brainpoolP256r1-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P384-SHA512",
        "MLDSA87-ECDSA-brainpoolP384r1-SHA512",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448",
        "MLDSA87-RSA3072-PSS-SHA512",
        "MLDSA87-RSA4096-PSS-SHA512"
    })
    public void testWrongKeyFails(String algorithm) throws Exception {
        KeyPair kp1 = generateKeyPair(algorithm);
        KeyPair kp2 = generateKeyPair(algorithm);

        Signature signing = Signature.getInstance(algorithm, getProviderName());
        signing.initSign(kp1.getPrivate());
        signing.update(origMsg);
        byte[] sig = signing.sign();

        Signature verifying = Signature.getInstance(algorithm, getProviderName());
        verifying.initVerify(kp2.getPublic());
        verifying.update(origMsg);

        assertFalse(verifying.verify(sig),
                "Verification with wrong key should fail for " + algorithm);
    }

    // -----------------------------------------------------------------------
    // Update called multiple times (chunked)
    // -----------------------------------------------------------------------

    @Test
    public void testChunkedUpdate_MLDSA44_ECDSAP256SHA256() throws Exception {
        String algorithm = "MLDSA44-ECDSA-P256-SHA256";
        KeyPair kp = generateKeyPair(algorithm);

        Signature signing = Signature.getInstance(algorithm, getProviderName());
        signing.initSign(kp.getPrivate());
        // Feed message in three chunks
        signing.update(origMsg, 0, 10);
        signing.update(origMsg, 10, origMsg.length - 10);
        byte[] sig = signing.sign();

        Signature verifying = Signature.getInstance(algorithm, getProviderName());
        verifying.initVerify(kp.getPublic());
        verifying.update(origMsg, 0, 5);
        verifying.update(origMsg, 5, origMsg.length - 5);

        assertTrue(verifying.verify(sig),
                "Chunked update verification failed");
    }

    // -----------------------------------------------------------------------
    // Helper
    // -----------------------------------------------------------------------

    private KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance(algorithm, getProviderName());
        return kpg.generateKeyPair();
    }
}
