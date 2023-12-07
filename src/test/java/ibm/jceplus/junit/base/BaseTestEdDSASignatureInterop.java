/*
 * Copyright IBM Corp. 2023
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.crypto.signers.Ed448Signer;

public class BaseTestEdDSASignatureInterop extends BaseTestSignature {

    // --------------------------------------------------------------------------
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    private static final SecureRandom RANDOM = new SecureRandom();

    //--------------------------------------------------------------------------
    //
    //
    public BaseTestEdDSASignatureInterop(String providerName) {
        super(providerName);
    }

    //--------------------------------------------------------------------------
    //
    //
    public void setUp() throws Exception {}

    //--------------------------------------------------------------------------
    //
    //
    public void tearDown() throws Exception {}

    public void testEd25519withEdDSA() throws Exception {
        KeyPair keyPair = generateKeyPair("Ed25519");
        byte[] signedMsg = doSign("Ed25519", origMsg, keyPair.getPrivate());
        doVerifyEd25519(origMsg, signedMsg, keyPair.getPublic());
    }

    public void testEd448withEdDSA() throws Exception {
        KeyPair keyPair = generateKeyPair("Ed448");
        byte[] signedMsg = doSign("Ed448", origMsg, keyPair.getPrivate());
        doVerifyEd448(origMsg, signedMsg, keyPair.getPublic());
    }

    private KeyPair generateKeyPair(String alg) throws Exception {
        KeyPairGenerator xecKeyPairGen = KeyPairGenerator.getInstance(alg, providerName);
        xecKeyPairGen.initialize(new NamedParameterSpec(alg));
        return xecKeyPairGen.generateKeyPair();
    }

    //--------------------------------------------------------------------------
    //
    //
    //Sign the message with OpenJCEPlus provided EdDSA
    private byte[] doSign(String sigAlgo, byte[] message, PrivateKey privateKey) throws Exception {
        Signature signing = Signature.getInstance(sigAlgo, providerName);
        signing.initSign(privateKey);
        signing.update(message);
        byte[] signedBytes = signing.sign();
        return signedBytes;
    }

    //--------------------------------------------------------------------------
    //
    //
    //Verify the message with BouncyCastle provided Ed25519
    protected void doVerifyEd25519(byte[] message, byte[] signedBytes, PublicKey publicKey)
            throws Exception {
        Ed25519PublicKeyParameters publicKeyBC = new Ed25519PublicKeyParameters(
                ((com.ibm.crypto.plus.provider.EdDSAPublicKeyImpl) publicKey).getEncodedPoint(), 0);
        Signer signer = new Ed25519Signer();
        signer.init(false, publicKeyBC);
        signer.update(message, 0, message.length);
        assertTrue("Signature verification failed ", signer.verifySignature(signedBytes));
    }

    //--------------------------------------------------------------------------
    //
    //
    //Verify the message with BouncyCastle provided Ed448
    protected void doVerifyEd448(byte[] message, byte[] signedBytes, PublicKey publicKey)
            throws Exception {
        Ed448PublicKeyParameters publicKeyBC = new Ed448PublicKeyParameters(
                ((com.ibm.crypto.plus.provider.EdDSAPublicKeyImpl) publicKey).getEncodedPoint(), 0);
        Signer signer = new Ed448Signer(new byte[0]);
        signer.init(false, publicKeyBC);
        signer.update(message, 0, message.length);
        assertTrue("Signature verification failed ", signer.verifySignature(signedBytes));
    }

}

