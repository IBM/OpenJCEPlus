/*
 * Copyright IBM Corp. 2026
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
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Base tests for Composite ML-DSA signature algorithms.
 *
 * <p>Covers:
 * <ol>
 *   <li>Key generation – public and private keys are non-null</li>
 *   <li>Sign / verify round-trip</li>
 *   <li>Domain separation – a tampered message must not verify</li>
 *   <li>Key encoding round-trip via X.509 / PKCS#8</li>
 *   <li>Key-reuse prohibition – re-signing different messages with the same key
 *       must produce different signatures (ML-DSA is randomized)</li>
 *   <li>Wrong-key rejection – a signature verified under a different key pair
 *       must fail</li>
 * </ol>
 */
public class BaseTestCompositeSig extends BaseTestJunit5 {

    private static final byte[] MSG =
            "The quick brown fox jumps over the lazy dog.".getBytes();

    // -----------------------------------------------------------------------
    // 1. Key generation
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testKeyGen(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        assertNotNull(kp.getPublic(), "Public key must not be null");
        assertNotNull(kp.getPrivate(), "Private key must not be null");
    }

    // -----------------------------------------------------------------------
    // 2. Sign / verify round-trip
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testSignVerify(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        byte[] sig = sign(algorithm, MSG, kp.getPrivate());
        assertTrue(verify(algorithm, MSG, sig, kp.getPublic()),
                "Signature must verify with the corresponding public key");
    }

    // -----------------------------------------------------------------------
    // 3. Domain separation – tampered message must not verify
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testTamperedMessageFails(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        byte[] sig = sign(algorithm, MSG, kp.getPrivate());

        byte[] tampered = MSG.clone();
        tampered[0] ^= 0xFF;

        assertFalse(verify(algorithm, tampered, sig, kp.getPublic()),
                "Tampered message must not verify");
    }

    // -----------------------------------------------------------------------
    // 4. Key encoding round-trip
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testKeyEncodingRoundTrip(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        KeyFactory kf = KeyFactory.getInstance(algorithm, getProviderName());

        byte[] pubEnc = kp.getPublic().getEncoded();
        byte[] privEnc = kp.getPrivate().getEncoded();

        PublicKey pub2 = kf.generatePublic(new X509EncodedKeySpec(pubEnc));
        PrivateKey priv2 = kf.generatePrivate(new PKCS8EncodedKeySpec(privEnc));

        byte[] sig = sign(algorithm, MSG, kp.getPrivate());
        assertTrue(verify(algorithm, MSG, sig, pub2),
                "Signature must verify after public key re-import");

        byte[] sig2 = sign(algorithm, MSG, priv2);
        assertTrue(verify(algorithm, MSG, sig2, kp.getPublic()),
                "Signature must verify after private key re-import");
    }

    // -----------------------------------------------------------------------
    // 5. Randomized signing – same key, different random bytes each time
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testSigningIsRandomized(String algorithm) throws Exception {
        KeyPair kp = generateKeyPair(algorithm);
        byte[] sig1 = sign(algorithm, MSG, kp.getPrivate());
        byte[] sig2 = sign(algorithm, MSG, kp.getPrivate());

        // ML-DSA is randomized; two signatures over the same message should
        // almost certainly differ (probability of collision is negligible).
        boolean identical = java.util.Arrays.equals(sig1, sig2);
        assertFalse(identical,
                "Two signatures of the same message should differ (ML-DSA is randomized)");
    }

    // -----------------------------------------------------------------------
    // 6. Wrong-key rejection
    // -----------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({
        "MLDSA44-ECDSA-P256-SHA256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P384-SHA512",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P521-SHA512",
        "MLDSA87-Ed448"
    })
    public void testWrongKeyFails(String algorithm) throws Exception {
        KeyPair kp1 = generateKeyPair(algorithm);
        KeyPair kp2 = generateKeyPair(algorithm);

        byte[] sig = sign(algorithm, MSG, kp1.getPrivate());

        try {
            boolean result = verify(algorithm, MSG, sig, kp2.getPublic());
            assertFalse(result, "Signature must not verify under a different public key");
        } catch (Exception e) {
            // Some implementations throw instead of returning false — that is also acceptable.
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private KeyPair generateKeyPair(String algorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, getProviderName());
        return kpg.generateKeyPair();
    }

    private byte[] sign(String algorithm, byte[] message, PrivateKey privateKey)
            throws Exception {
        Signature sig = Signature.getInstance(algorithm, getProviderName());
        sig.initSign(privateKey);
        sig.update(message);
        return sig.sign();
    }

    private boolean verify(String algorithm, byte[] message, byte[] sigBytes, PublicKey publicKey)
            throws Exception {
        Signature sig = Signature.getInstance(algorithm, getProviderName());
        sig.initVerify(publicKey);
        sig.update(message);
        return sig.verify(sigBytes);
    }
}
