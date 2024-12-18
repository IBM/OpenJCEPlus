/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestEdDSASignatureInterop extends BaseTestJunit5Signature {

    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    public void testEd25519withEdDSA() throws Exception {
        KeyPair keyPair = generateKeyPair("Ed25519");
        byte[] signedMsg = doSign("Ed25519", origMsg, keyPair.getPrivate());
        doVerifyEd25519(origMsg, signedMsg, keyPair.getPublic());
    }

    @Test
    public void testEd448withEdDSA() throws Exception {
        KeyPair keyPair = generateKeyPair("Ed448");
        byte[] signedMsg = doSign("Ed448", origMsg, keyPair.getPrivate());
        doVerifyEd448(origMsg, signedMsg, keyPair.getPublic());
    }

    private KeyPair generateKeyPair(String alg) throws Exception {
        KeyPairGenerator xecKeyPairGen = KeyPairGenerator.getInstance(alg, getProviderName());
        xecKeyPairGen.initialize(new NamedParameterSpec(alg));
        return xecKeyPairGen.generateKeyPair();
    }


    //Sign the message with OpenJCEPlus provided EdDSA
    private byte[] doSign(String sigAlgo, byte[] message, PrivateKey privateKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, getProviderName());
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();
        return signedBytes;
    }


    //Verify the message with BouncyCastle provided Ed25519
    protected void doVerifyEd25519(byte[] message, byte[] signedBytes, PublicKey publicKey)
            throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", getProviderName());
        EdECPublicKeySpec keySpec = keyFactory.getKeySpec(publicKey, EdECPublicKeySpec.class);
        EdECPoint point = keySpec.getPoint();
        byte[] encodedPoint = point.getY().toByteArray();
        reverseByteArray(encodedPoint);
        byte setMSB = point.isXOdd() ? (byte)0x80 : (byte)0x00;
        encodedPoint[encodedPoint.length - 1] |= setMSB;

        Ed25519PublicKeyParameters publicKeyBC = new Ed25519PublicKeyParameters(encodedPoint);
        Signer signer = new Ed25519Signer();
        signer.init(false, publicKeyBC);
        signer.update(message, 0, message.length);
        assertTrue(signer.verifySignature(signedBytes), "Signature verification failed ");
    }


    //Verify the message with BouncyCastle provided Ed448
    protected void doVerifyEd448(byte[] message, byte[] signedBytes, PublicKey publicKey)
            throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", getProviderName());
        EdECPublicKeySpec keySpec = keyFactory.getKeySpec(publicKey, EdECPublicKeySpec.class);
        EdECPoint point = keySpec.getPoint();
        byte[] originalEncodedPoint = point.getY().toByteArray();
        reverseByteArray(originalEncodedPoint);
        byte[] encodedPoint = java.util.Arrays.copyOf(originalEncodedPoint, 57);
        byte setMSB = point.isXOdd() ? (byte)0x80 : (byte)0x00;
        encodedPoint[encodedPoint.length - 1] = setMSB;

        Ed448PublicKeyParameters publicKeyBC = new Ed448PublicKeyParameters(encodedPoint);
        Signer signer = new Ed448Signer(new byte[0]);
        signer.init(false, publicKeyBC);
        signer.update(message, 0, message.length);
        assertTrue(signer.verifySignature(signedBytes), "Signature verification failed ");
    }

    private static void reverseByteArray(byte[] arr) throws IOException {
        for (int i = 0; i < arr.length / 2; i++) {
            byte temp = arr[i];
            arr[i] = arr[arr.length - 1 - i];
            arr[arr.length - 1 - i] = temp;
        }
    }

}

