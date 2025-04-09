/*
 * Copyright IBM Corp. 2023, 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestEdDSASignatureInterop extends BaseTestJunit5Interop {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    static final String EDDSA_ALG_NAME = "EdDSA";

    @ParameterizedTest
    @MethodSource("testEdDSAArguments")
    public void testEdDSA(String KeyPairAlg, byte[] message, String provider1, String provider2)
            throws Exception {
        KeyPair keyPair = generateKeyPair(KeyPairAlg, provider1);
        byte[] signedMsg = doSign(message, keyPair.getPrivate(), provider1);
        doVerify(message, signedMsg, keyPair.getPublic(), provider2);
    }

    private Stream<Arguments> testEdDSAArguments() {
        return Stream.of(
                Arguments.of("Ed25519", origMsg, getProviderName(), getInteropProviderName()),
                Arguments.of("Ed25519", origMsg, getInteropProviderName(), getProviderName()),
                Arguments.of("Ed448", origMsg, getProviderName(), getInteropProviderName()),
                Arguments.of("Ed448", origMsg, getInteropProviderName(), getProviderName()),
                Arguments.of("Ed448", null, getProviderName(), getInteropProviderName()),
                Arguments.of("Ed448", null, getInteropProviderName(), getProviderName()),
                Arguments.of("Ed25519", null, getProviderName(), getInteropProviderName()),
                Arguments.of("Ed25519", null, getInteropProviderName(), getProviderName()));
    }

    private KeyPair generateKeyPair(String alg, String providerName) throws Exception {
        KeyPairGenerator xecKeyPairGen = KeyPairGenerator.getInstance(alg, providerName);
        xecKeyPairGen.initialize(new NamedParameterSpec(alg));
        return xecKeyPairGen.generateKeyPair();
    }

    /**
     * Sign a message.
     *
     * @param message The message to sign. This can be null in which no message will be used.
     * @param privateKey The private key to sign the message with.
     * @param providerName The name of the provider to instantiate the message `sigAlgo` with.
     * @return A byte array that contains the resulting signature.
     * @throws Exception
     */
    private byte[] doSign(byte[] message, PrivateKey privateKey, String providerName)
            throws Exception {
        Signature signing = Signature.getInstance(EDDSA_ALG_NAME, providerName);
        signing.initSign(privateKey);
        if (message != null) {
            signing.update(message);
        }
        byte[] signedBytes = signing.sign();
        return signedBytes;
    }

    /**
     * Verify a signature.
     *
     * @param message The message to verify. This can be null in which no message will be used.
     * @param signedBytes The signature bytes.
     * @param publicKey The public key used to verify the message.
     * @param providerName he name of the provider to instantiate the message `sigAlgo` with.
     * @throws Exception
     */
    protected void doVerify(byte[] message, byte[] signedBytes, PublicKey publicKey,
            String providerName) throws Exception {

        Signature verify = Signature.getInstance(EDDSA_ALG_NAME, providerName);
        verify.initVerify(publicKey);
        if (message != null) {
            verify.update(message, 0, message.length);
        }
        assertTrue(verify.verify(signedBytes), "Signature verification failed.");
    }
}
