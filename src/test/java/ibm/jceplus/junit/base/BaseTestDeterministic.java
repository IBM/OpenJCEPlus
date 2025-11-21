/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import ibm.security.internal.spec.CCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameterGenerator;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class BaseTestDeterministic extends BaseTestJunit5 {
    private static final long SEED = 0;
    private static int hash = 0;

    @Test
    public void testServices() throws Exception {
        Provider p = Security.getProvider(getProviderName());
        for (var s : p.getServices()) {
            switch (s.getType()) {
                case "KeyPairGenerator" -> testKeyPairGenerator(s);
                case "KeyGenerator" -> testKeyGenerator(s);
                case "Signature" -> testSignature(s);
                case "KeyAgreement" -> testKeyAgreement(s);
                case "Cipher" -> testCipher(s);
                case "AlgorithmParameterGenerator" -> testAlgorithmParameterGenerator(s);
            }
        }
    }

    static void testCipher(Provider.Service s) throws Exception {
        var alg = s.getAlgorithm();
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + alg);
        if (alg.contains("Wrap") || alg.contains("KW")) {
            System.out.println("    Ignored");
            return;
        }
        Key key;
        AlgorithmParameterSpec spec;
        if (alg.startsWith("PBE")) {
            key = new SecretKeySpec("isthisakey".getBytes(StandardCharsets.UTF_8), "PBE");
            // Some cipher requires salt to be 8 byte long
            spec = new PBEParameterSpec("saltsalt".getBytes(StandardCharsets.UTF_8), 100);
        } else {
            key = generateKey(alg.split("/")[0], s.getProvider());
            if (!alg.contains("/") || alg.contains("/ECB/")) {
                spec = null;
            } else {
                if (alg.contains("/GCM/")) {
                    spec = new GCMParameterSpec(128,
                            new SeededSecureRandom(SEED + 1).generateSeed(16));
                } else if (alg.contains("/CCM/")) {
                    spec = new CCMParameterSpec(128,
                            new SeededSecureRandom(SEED + 1).generateSeed(13)); // CCM iv is 7 to 13 bytes inclusive in OpenJCEPlus.
                } else if (alg.equals("ChaCha20")) {
                    spec = new ChaCha20ParameterSpec(
                            new SeededSecureRandom(SEED + 2).generateSeed(12), 128);
                } else if (alg.contains("ChaCha20")) {
                    spec = new IvParameterSpec(new SeededSecureRandom(SEED + 3).generateSeed(12));
                } else {
                    spec = new IvParameterSpec(new SeededSecureRandom(SEED + 4).generateSeed(16));
                }
            }
        }
        var c = Cipher.getInstance(alg, s.getProvider());
        c.init(Cipher.ENCRYPT_MODE, key, spec, new SeededSecureRandom(SEED));
        // Some cipher requires plaintext to be 16 byte long
        var ct1 = c.doFinal("asimpleplaintext".getBytes(StandardCharsets.UTF_8));
        // Some cipher requires IV to be different, so re-instantiate a cipher
        c = Cipher.getInstance(alg, s.getProvider());
        c.init(Cipher.ENCRYPT_MODE, key, spec, new SeededSecureRandom(SEED));
        var ct2 = c.doFinal("asimpleplaintext".getBytes(StandardCharsets.UTF_8));

        String algorithm = s.getAlgorithm();
        if ((algorithm.equals("RSA") || algorithm.contains("ChaCha20"))) {
            //OpenJCEPlus ignores random generators used when initializing ciphers.
            System.out.println(
                    "OpenJCEPlus ignores random generators used within Ciphers: " + algorithm);
            assertThat(ct1, not(equalTo(ct2)));
        } else {
            assertArrayEquals(ct1, ct2);
        }
        hash = Objects.hash(hash, Arrays.hashCode(ct1));
        System.out.println("    Passed");
    }

    static void testAlgorithmParameterGenerator(Provider.Service s) throws Exception {
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + s.getAlgorithm());
        var apg = AlgorithmParameterGenerator.getInstance(s.getAlgorithm(), s.getProvider());
        AlgorithmParameterSpec p1 = null;
        AlgorithmParameterSpec p2 = null;

        String algorithm = s.getAlgorithm();
        if (algorithm.equals("CCM") || algorithm.equals("GCM")) {
            apg.init(128, new SeededSecureRandom(SEED));
            p1 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
            apg.init(128, new SeededSecureRandom(SEED));
            p2 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
            return; // Return since there is currently no way to compare the values within a
                    // CCM or GCM parameter spec to another one.
        } else if (algorithm.equals("EC")) {
            apg.init(521, new SeededSecureRandom(SEED));
            p1 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
            apg.init(521, new SeededSecureRandom(SEED));
            p2 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
        } else {
            apg.init(2048, new SeededSecureRandom(SEED));
            p1 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
            apg.init(2048, new SeededSecureRandom(SEED));
            p2 = apg.generateParameters().getParameterSpec(AlgorithmParameterSpec.class);
        }

        if (p1 instanceof DSAParameterSpec d1 && p2 instanceof DSAParameterSpec d2) {
            assertEquals(d1.getG(), d2.getG());
            assertEquals(d1.getP(), d2.getP());
            assertEquals(d1.getQ(), d2.getQ());
            hash = Objects.hash(hash, d1.getG(), d1.getP(), d1.getQ());
        } else if (p1 instanceof DHParameterSpec d1 && p2 instanceof DHParameterSpec d2) {
            assertEquals(d1.getG(), d2.getG());
            assertEquals(d1.getP(), d2.getP());
            assertEquals(d1.getL(), d2.getL());
            hash = Objects.hash(hash, d1.getG(), d1.getP(), d1.getL());
        } else {
            assertEquals(p1, p2);
            hash = Objects.hash(hash, p1);
        }
        System.out.println("    Passed");
    }

    private static void testSignature(Provider.Service s) throws Exception {
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + s.getAlgorithm());
        String keyAlg = s.getAlgorithm();
        String keyProvider = s.getProvider().getName();

        // The OpenJCEPlusFIPS provider does not allow for signing with SHA1withRSA
        // OpenJCEPlusFIPS provider does not have a DSA key generator so these
        // signature tests can be skipped.
        if (s.getProvider().getName().equals("OpenJCEPlusFIPS")
                && (s.getAlgorithm().equals("SHA1withRSA") || s.getAlgorithm().contains("withDSA"))) {
            System.out.println(
                    "Skipping variation for OpenJCEPlusFIPS provider. Not supported in FIPS.");
            System.out.println("    Ignored");
            return;
        }

        if (s.getAlgorithm().equals("RSAforSSL")) {
            keyAlg = "RSA"; // RSA keys are used for the RSAforSSL signature within OpenJCEPlus
        }

        if (s.getAlgorithm().contains("withRSA")) {
            keyAlg = "RSA"; // RSA keys are used for the RSAforSSL signature within OpenJCEPlus
        }

        if (s.getAlgorithm().contains("withDSA")) {
            keyAlg = "DSA"; // RSA keys are used for the RSAforSSL signature within OpenJCEPlus
        }

        if (s.getAlgorithm().contains("withECDSA")) {
            keyAlg = "EC"; // RSA keys are used for the RSAforSSL signature within OpenJCEPlus
        }

        var sk = generateKeyPair(keyAlg, keyProvider, 0).getPrivate();
        var sig = Signature.getInstance(s.getAlgorithm(), s.getProvider());
        try {
            if (keyAlg.equals("RSASSA-PSS")) {
                sig.setParameter(PSSParameterSpec.DEFAULT);
            }
            sig.initSign(sk, new SeededSecureRandom(SEED));
            sig.update(new byte[20]);
            var s1 = sig.sign();
            sig.initSign(sk, new SeededSecureRandom(SEED));
            sig.update(new byte[20]);
            var s2 = sig.sign();
            System.out.println("Provider: " + sig.getProvider().getName());

            String algorithm = s.getAlgorithm();
            if ((algorithm.equals("Ed448")) || (algorithm.equals("Ed25519"))
                    || (algorithm.contains("withRSA")) || (algorithm.equals("RSAforSSL"))
                    || (algorithm.equals("EdDSA"))) {
                // Some algorithms such as these are deterministic and already ignore random seeds anyway.
                System.out.println(
                        "Algorithm is deterministic and ignores randoms anyway: " + algorithm);
                assertArrayEquals(s1, s2);
            } else {
                // OpenJCEPlus and OpenJCEPlusFIPS ignores specified random generators
                // used when initializing signatures.
                assertThat(s1, not(equalTo(s2)));
            }

            hash = Objects.hash(hash, Arrays.hashCode(s1));
            System.out.println("    Passed");
        } catch (InvalidKeyException ike) {
            System.out.println("    Ignored: " + ike.getMessage());
        }
    }

    static void testKeyPairGenerator(Provider.Service s) throws Exception {
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + s.getAlgorithm());
        var kp1 = generateKeyPair(s.getAlgorithm(), s.getProvider().getName(), 0);
        var kp2 = generateKeyPair(s.getAlgorithm(), s.getProvider().getName(), 0);

        //OpenJCEPlus ignores random generators used when generating keys.
        System.out.println("OpenJCEPlus ignores random generators used when generating keys.");
        assertThat(kp1.getPrivate().getEncoded(), not(equalTo(kp2.getPrivate().getEncoded())));
        assertThat(kp1.getPublic().getEncoded(), not(equalTo(kp2.getPublic().getEncoded())));

        hash = Objects.hash(hash, Arrays.hashCode(kp1.getPrivate().getEncoded()),
                Arrays.hashCode(kp1.getPublic().getEncoded()));
        System.out.println("    Passed");
    }

    static KeyPair generateKeyPair(String alg, String p, int offset) throws Exception {
        var g = KeyPairGenerator.getInstance(alg, p);
        var size = switch (g.getAlgorithm()) {
            case "RSA", "RSASSA-PSS", "RSAPSS", "DSA", "DiffieHellman" -> 2048;
            case "EC" -> 256;
            case "EdDSA", "Ed25519", "XDH", "X25519" -> 255;
            case "Ed448", "X448" -> 448;
            case "ML-KEM", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024" -> 0;
            case "ML-DSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" -> 0;
            default -> throw new UnsupportedOperationException(alg);
        };
        if (size != 0) {
            g.initialize(size, new SeededSecureRandom(SEED + offset));
        }
        return g.generateKeyPair();
    }

    static void testKeyGenerator(Provider.Service s) throws Exception {
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + s.getAlgorithm());
        if (s.getAlgorithm().startsWith("SunTls")) {
            System.out.println("    Ignored");
            return;
        } else if (s.getAlgorithm().startsWith("kda-hkdf-with-")) {
            // Skip this test as this algorithm contains OpenJCEPlus specific behavior
            // similar in nature to the SunTls algorithms.
            System.out.println("    Ignored");
            return;
        }
        var k1 = generateKey(s.getAlgorithm(), s.getProvider());
        var k2 = generateKey(s.getAlgorithm(), s.getProvider());
        assertThat(k1.getEncoded(), not(equalTo(k2.getEncoded())));

        hash = Objects.hash(hash, Arrays.hashCode(k1.getEncoded()));
        System.out.println("    Passed");
    }

    static Key generateKey(String s, Provider p) throws Exception {
        if (s.startsWith("AES_")) {
            var g = KeyGenerator.getInstance("AES", p);
            g.init(Integer.parseInt(s.substring(4)), new SeededSecureRandom(SEED + 1));
            return g.generateKey();
        }
        if (s.startsWith("ChaCha")) {
            var g = KeyGenerator.getInstance("ChaCha20", p);
            g.init(new SeededSecureRandom(SEED + 2));
            return g.generateKey();
        }
        if (s.equals("RSA")) {
            return generateKeyPair("RSA", p.getName(), 3).getPublic();
        } else {
            var g = KeyGenerator.getInstance(s, p);
            g.init(new SeededSecureRandom(SEED + 4));
            return g.generateKey();
        }
    }

    static void testKeyAgreement(Provider.Service s) throws Exception {
        String keyAlg = getKeyAlgFromKEM(s.getAlgorithm());
        System.out.println(s.getProvider().getName() + " " + s.getType() + "." + s.getAlgorithm() + " keyAlg: " + keyAlg);
        var kpS = generateKeyPair(keyAlg, s.getProvider().getName(), 11);
        var kpR = generateKeyPair(keyAlg, s.getProvider().getName(), 12);
        var ka = KeyAgreement.getInstance(s.getAlgorithm(), s.getProvider());
        ka.init(kpS.getPrivate(), new SeededSecureRandom(SEED));
        ka.doPhase(kpR.getPublic(), true);
        var sc1 = ka.generateSecret();
        ka.init(kpS.getPrivate(), new SeededSecureRandom(SEED));
        ka.doPhase(kpR.getPublic(), true);
        var sc2 = ka.generateSecret();

        // Since randoms are generally ignored for KeyAgreement
        // we can expect equal results, even though we sent in our
        // test seeded secure random.
        assertArrayEquals(sc1, sc2);
        hash = Objects.hash(hash, Arrays.hashCode(sc1));
        System.out.println("    Passed");
    }

    static String getKeyAlgFromKEM(String algorithm) {
        return switch (algorithm) {
            case "DHKEM" -> "X25519";
            case "ECDH" -> "EC";
            default -> algorithm;
        };
    }

    public static class SeededSecureRandom extends SecureRandom {

        private final Random rnd;

        public static long seed() {
            String value = System.getProperty("secure.random.seed");
            long seed = value != null ? Long.parseLong(value) : new Random().nextLong();
            System.out.println("SeededSecureRandom: seed = " + seed);
            return seed;
        }

        public SeededSecureRandom(long seed) {
            rnd = new Random(seed);
        }

        public static SeededSecureRandom one() {
            return new SeededSecureRandom(seed());
        }

        @Override
        public void nextBytes(byte[] bytes) {
            rnd.nextBytes(bytes);
        }

        @Override
        public byte[] generateSeed(int numBytes) {
            var out = new byte[numBytes];
            rnd.nextBytes(out);
            return out;
        }
    }
}
