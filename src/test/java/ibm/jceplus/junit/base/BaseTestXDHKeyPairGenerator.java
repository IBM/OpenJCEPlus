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
import java.security.interfaces.XECPrivateKey;
import java.security.interfaces.XECPublicKey;
import org.junit.Before;
import ibm.security.internal.spec.NamedParameterSpec;

public class BaseTestXDHKeyPairGenerator extends ibm.jceplus.junit.base.BaseTest {

    KeyPairGenerator kpg = null;
    KeyPairGenerator kpgc = null;

    @Before
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        kpg = KeyPairGenerator.getInstance("XDH", providerName);
        kpgc = KeyPairGenerator.getInstance("XDH", providerName);
    }

    public BaseTestXDHKeyPairGenerator(String providerName) {
        super(providerName);
    }

    public void tearDown() throws Exception {}

    public void testXECKeyGen_X255() throws Exception {
        doXECKeyGen(255);
    }

    public void testXECKeyGen_X448() throws Exception {
        doXECKeyGen(448);
    }

    public void testXECKeyGen_FFDHE2048() throws Exception {
        doXECKeyGen(2048);
    }

    public void testXECKeyGen_FFDHE3072() throws Exception {
        doXECKeyGen(3072);
    }

    public void testXECKeyGen_FFDHE4096() throws Exception {
        doXECKeyGen(4096);
    }

    public void testXECKeyGen_FFDHE6144() throws Exception {
        doXECKeyGen(6144);
    }

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

