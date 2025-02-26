/*
 * Copyright IBM Corp. 2023, 2024
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
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import sun.security.util.InternalPrivateKey;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BaseTestXDHKeyPairGenerator extends BaseTestJunit5 {

    KeyPairGenerator kpg = null;
    KeyPairGenerator kpgc = null;

    @BeforeEach
    public void setUp() throws Exception {
        kpg = KeyPairGenerator.getInstance("XDH", getProviderName());
        kpgc = KeyPairGenerator.getInstance("XDH", getProviderName());
    }

    @Test
    public void testXECKeyGen_X255() throws Exception {
        doXECKeyGen(255);
    }

    @Test
    public void testXECKeyGen_X448() throws Exception {
        doXECKeyGen(448);
    }

    @Test
    public void testXECKeyGen_FFDHE2048() throws Exception {
        doXECKeyGen(2048);
    }

    @Test
    public void testXECKeyGen_FFDHE3072() throws Exception {
        doXECKeyGen(3072);
    }

    @Test
    public void testXECKeyGen_FFDHE4096() throws Exception {
        doXECKeyGen(4096);
    }

    @Test
    public void testXECKeyGen_FFDHE6144() throws Exception {
        doXECKeyGen(6144);
    }

    @Test
    public void testXECKeyGen_FFDHE8192() throws Exception {
        doXECKeyGen(8192);
    }

    public void doXECKeyGen(int keypairSize) throws Exception {
        kpg.initialize(keypairSize);
        KeyPair kp = kpg.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        XECPublicKey xecpu = (XECPublicKey) kp.getPublic();
        XECPrivateKey xecpr = (XECPrivateKey) kp.getPrivate();

        assert (xecpu.getU() != null);
        assert (xecpr.getScalar() != null);

        //System.out.println("---- EC keypair for key size " + keypairSize + "  ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }

    @Test
    public void testXDHPrivateKey_calculatePublicKey() throws Exception {
        kpg.initialize(255);
        KeyPair kp = kpg.generateKeyPair();

        PublicKey ecpu = kp.getPublic();
        PrivateKey ecpr = kp.getPrivate();

        byte[] originalEncoded = ecpu.getEncoded();
        byte[] calculatedEncoded = ((InternalPrivateKey) ecpr).calculatePublicKey().getEncoded();

        System.out.println("---- Comparing XDH public key from KeyPair vs calculated from private key ----");
        System.out.println("XDH public key from Keypair: " + BaseUtils.bytesToHex(originalEncoded));
        System.out.println("XDH public key from calculatePublicKey(): " + BaseUtils.bytesToHex(calculatedEncoded));
        assertArrayEquals(originalEncoded, calculatedEncoded);
    }

    @Test
    public void testXECKeyGenCurves() throws Exception {
        generictestXECKeyGenCurve("X25519");
        generictestXECKeyGenCurve("X448");
        generictestXECKeyGenCurve("FFDHE2048");
        generictestXECKeyGenCurve("FFDHE3072");
        generictestXECKeyGenCurve("FFDHE4096");
        generictestXECKeyGenCurve("FFDHE6144");
        generictestXECKeyGenCurve("FFDHE8192");
        generictestXECKeyGenCurve("Ed25519");
        generictestXECKeyGenCurve("Ed448");
    }

    protected void generictestXECKeyGenCurve(String curveName) throws Exception {
        NamedParameterSpec nps = new NamedParameterSpec(curveName);
        kpgc.initialize(nps);
        KeyPair kp = kpgc.generateKeyPair();

        assert (kp != null);

        assert (kp.getPublic() != null);
        assert (kp.getPrivate() != null);

        XECPublicKey xecpu = (XECPublicKey) kp.getPublic();
        XECPrivateKey xecpr = (XECPrivateKey) kp.getPrivate();

        assert (xecpu.getU() != null);
        assert (xecpr.getScalar() != null);

        //System.out.println("---- 192 test ----");
        //System.out.println("ECPublic (x,y): (" + ecpu.getW().getAffineX() + ", " + ecpu.getW().getAffineY() + ")");
        //System.out.println("ECPrivate: " + ecpr.getS());
    }
}

