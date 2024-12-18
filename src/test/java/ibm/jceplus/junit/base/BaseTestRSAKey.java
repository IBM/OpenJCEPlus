/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */
package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestRSAKey extends BaseTestJunit5 {


    protected KeyPairGenerator rsaKeyPairGen;
    protected KeyFactory rsaKeyFactory;

    @BeforeEach
    public void setUp() throws Exception {
        rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyFactory = KeyFactory.getInstance("RSA", getProviderName());
    }

    @Test
    public void testRSAKeyGen_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        KeyPair rsaKeyPair = generateKeyPair(1024);
        rsaKeyPair.getPublic();
        rsaKeyPair.getPrivate();
    }

    @Test
    public void testRSAKeyGen_2048() throws Exception {
        KeyPair rsaKeyPair = generateKeyPair(2048);
        rsaKeyPair.getPublic();
        rsaKeyPair.getPrivate();
    }

    @Test
    public void testRSAKeyGen_4096() throws Exception {
        KeyPair rsaKeyPair = generateKeyPair(4096);
        rsaKeyPair.getPublic();
        rsaKeyPair.getPrivate();
    }

    @Test
    public void testRSAKeyFactoryCreateFromEncoded_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        keyFactoryCreateFromEncoded(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromEncoded_2048() throws Exception {
        keyFactoryCreateFromEncoded(2048);
    }

    @Test
    public void testRSAKeyFactoryCreateFromEncoded_4096() throws Exception {
        keyFactoryCreateFromEncoded(4096);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpec_1024() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        keyFactoryCreateFromKeySpec(1024);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpec_2048() throws Exception {
        keyFactoryCreateFromKeySpec(2048);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpec_4096() throws Exception {
        keyFactoryCreateFromKeySpec(4096);
    }

    @Test
    public void testRSAKeyFactoryCreateFromKeySpec() throws Exception {

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support 1024 bit keys
            return;
        }
        RSAPrivateCrtKeySpec crtSpec = new RSAPrivateCrtKeySpec(
                new BigInteger("00BF6097526F553D345A702A86DA69A3C98379EFC52BD9246DBDD7F75B17CA115"
                        + "102F379E5F59715D41F5A6FD5F8EE70E2ECD6813222FF1E45D7742C5E823C3BE382AFC564701B83D674F463"
                        + "04290456408E7CD638322F3D461AFB6B8529AD3A7902CA12E8AF9D8F5C267A930CFFD9E13B3A12CDE2784C"
                        + "2E797572A344C3698327", 16),
                new BigInteger("010001", 16),
                new BigInteger(
                        "35067FD704E702BED34219DE647CF9B737791D30ADFE0BC4666204F4D5EA149334349E"
                                + "F552EF4A4A8C6763EE4EFB4E06EA256305AFC1AD331FC7DE154F937DEA07F83D60ED645167EFBF19357B6BF593DA1BAD"
                                + "640FA1C230771970AADF94AAF75636DEDC3D8795E50242101866A9D99620193C46921F8542688D8F377593BD0D",
                        16),
                new BigInteger("00F559F092F829CDF2224C2C106F1CDFA0AF3EF5EAF22687EE1FB34E0BD6816D91"
                        + "45D0D618BE63B88B7483C9B2ABB9CE5836D22A5700B03B8F5923723C26F0A193", 16),
                new BigInteger("00C7AEF458A31A1C85B72ED67DE9EA7E95E52092C5E6B43E03AD930CBA60"
                        + "81DE583060A728DA778FC4405FF06B4C8EE1943E7E9DA3F33110E1870A1099CA03649D",
                        16),
                new BigInteger("00DA359E9827EC8E44EEAA0E7AA347EBC06E7C319D3EB674289DBB"
                        + "0C0BCD4099611DD5C9C481F810D6BECEC3218C4799B4AD352800EF14CE3404D458B214F3E8CF",
                        16),
                new BigInteger("00916B20F937F679150BFD69291363B9421235F18D7BE081"
                        + "550E600BA1E34C508F2AD4088820E97762757B28CC0B59F67F8E2F893FEF88290204E4D88816ECF7A5",
                        16),
                new BigInteger(
                        "05A8AA2383DE604F6A77AFDBC88B517226434F2E331261484A11128F1D6ED29D068A20B7B1"
                                + "48219A23BD70BF9FAEE7AA795D5A8537C90E88D3E4F8CA146907CB",
                        16));

        RSAPrivateCrtKey rsaPriv = (RSAPrivateCrtKey) rsaKeyFactory.generatePrivate(crtSpec);

        RSAPublicKeySpec rsaPublicSpec = new RSAPublicKeySpec(rsaPriv.getModulus(),
                rsaPriv.getPublicExponent());
        rsaKeyFactory.generatePublic(rsaPublicSpec);
    }


    protected KeyPair generateKeyPair(int size) throws Exception {
        rsaKeyPairGen.initialize(size);
        KeyPair keyPair = rsaKeyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("RSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof RSAPrivateKey)) {
            fail("Private key is not a RSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof RSAPublicKey)) {
            fail("Private key is not a RSAPublicKey");
        }

        return keyPair;
    }


    protected void keyFactoryCreateFromEncoded(int size) throws Exception {

        KeyPair rsaKeyPair = generateKeyPair(size);

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(rsaKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                rsaKeyPair.getPrivate().getEncoded());

        RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyFactory.generatePublic(x509Spec);
        RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(rsaPub.getEncoded(), rsaKeyPair.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPriv.getEncoded(), rsaKeyPair.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }
    }


    protected void keyFactoryCreateFromKeySpec(int size) throws Exception {

        KeyPair rsaKeyPair = generateKeyPair(size);

        RSAPublicKeySpec rsaPubSpec = rsaKeyFactory
                .getKeySpec(rsaKeyPair.getPublic(), RSAPublicKeySpec.class);
        RSAPublicKey rsaPub = (RSAPublicKey) rsaKeyFactory.generatePublic(rsaPubSpec);

        if (!Arrays.equals(rsaPub.getEncoded(), rsaKeyPair.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (rsaKeyPair.getPrivate() instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKeySpec rsaPrivateCrtSpec = rsaKeyFactory
                    .getKeySpec(rsaKeyPair.getPrivate(), RSAPrivateCrtKeySpec.class);
            RSAPrivateCrtKey rsaPrivCrt = (RSAPrivateCrtKey) rsaKeyFactory
                    .generatePrivate(rsaPrivateCrtSpec);

            if (!Arrays.equals(rsaPrivCrt.getEncoded(), rsaKeyPair.getPrivate().getEncoded())) {
                fail("RSA private CRT key does not match generated private key");
            }

            RSAPrivateKeySpec rsaPrivateSpec = rsaKeyFactory
                    .getKeySpec(rsaKeyPair.getPrivate(), RSAPrivateKeySpec.class);
            try {
                //JCEPlus does not support RSAPrivateKeySpec
                rsaKeyFactory.generatePrivate(rsaPrivateSpec);
                /*fail("JCEPlus should require RSA private keys to be CRT (Chinese Remainder Theorem) key");*/
            } catch (InvalidKeySpecException ikse) {
                //assertTrue("JCEPlus requires RSA private keys to be CRT (Chinese Remainder Theorem) keys", true);
                assertTrue(false, "JCEPlus InvalidKeySpeccException = " + ikse.getMessage());
            }
        } else {
            RSAPrivateKeySpec rsaPrivateSpec = rsaKeyFactory
                    .getKeySpec(rsaKeyPair.getPrivate(), RSAPrivateKeySpec.class);
            RSAPrivateKey rsaPriv = (RSAPrivateKey) rsaKeyFactory.generatePrivate(rsaPrivateSpec);

            if (!Arrays.equals(rsaPriv.getEncoded(), rsaKeyPair.getPrivate().getEncoded())) {
                fail("RSA private key does not match generated private key");
            }
        }
    }
}

