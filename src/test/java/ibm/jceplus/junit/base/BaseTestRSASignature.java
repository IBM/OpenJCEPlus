/*
 * Copyright IBM Corp. 2023, 2024
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.base;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class BaseTestRSASignature extends BaseTestSignature {

    //--------------------------------------------------------------------------
    //
    //
    static final byte[] origMsg = "this is the original message to be signed".getBytes();

    static final BigInteger N = new BigInteger(
            "116231208661367609700141079576488663663527180869991078124978203037949869"
                    + "312762870627991319537001781149083155962615105864954367253799351549459177"
                    + "839995715202060014346744789001273681801687605044315560723525700773069112"
                    + "214443196787519930666193675297582113726306864236010438506452172563580739"
                    + "994193451997175316921");

    static final BigInteger E = BigInteger.valueOf(65537);

    static final BigInteger D = new BigInteger(
            "528278531576995741358027120152717979850387435582102361125581844437708890"
                    + "736418759997555187916546691958396015481089485084669078137376029510618510"
                    + "203389286674134146181629472813419906337170366867244770096128371742241254"
                    + "843638089774095747779777512895029847721754360216404183209801002443859648"
                    + "26168432372077852785");

    @Test
    public void testRSAPlainKeySignature() throws Exception {

        KeyFactory kf;

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support plain keys
            return;
        }

        kf = KeyFactory.getInstance("RSA", getProviderName());

        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(N, E);
        PublicKey publicKey = kf.generatePublic(pubSpec);

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(N, D);
        PrivateKey privateKey = kf.generatePrivate(privSpec);

        doSignVerify("SHA1withRSA", origMsg, privateKey, publicKey);
    }

    @Test
    public void testRSAPlainKeySSLSignature() throws Exception {

        KeyFactory kf;

        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support plain keys
            return;
        }

        kf = KeyFactory.getInstance("RSA", getProviderName());

        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(N, E);
        PublicKey publicKey = kf.generatePublic(pubSpec);

        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(N, D);
        PrivateKey privateKey = kf.generatePrivate(privSpec);

        doSignVerify("RSAforSSL", origMsg, privateKey, publicKey);
    }

    @Test
    public void testSHA1withRSA() throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //SHA1 not supported in FIPS
            return;
        }
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA1withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA224withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA224withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA256withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA256withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA384withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA384withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA512withRSA() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        doSignVerify("SHA512withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testSHA3_224withRSA() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(getKeySize());
            doSignVerify("SHA3-224withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_256withRSA() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(getKeySize());
            doSignVerify("SHA3-256withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_384withRSA() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(getKeySize());
            doSignVerify("SHA3-384withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testSHA3_512withRSA() throws Exception {
        try {
            KeyPair keyPair = generateKeyPair(getKeySize());
            doSignVerify("SHA3-512withRSA", origMsg, keyPair.getPrivate(), keyPair.getPublic());
        } catch (InvalidParameterException | InvalidKeyException | NoSuchAlgorithmException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testRSAforSSL_hash1() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 1);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testRSAforSSL_hash5() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 5);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testRSAforSSL_hash20() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 20);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testRSAforSSL_hash36() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 36);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testRSAforSSL_hash40() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 40);
        doSignVerify("RSAforSSL", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testNONEwithRSA_hash1() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 1);
        doSignVerify("NONEwithRSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testNONEwithRSA_hash5() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 5);
        doSignVerify("NONEwithRSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testNONEwithRSA_hash20() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 20);
        doSignVerify("NONEwithRSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testNONEwithRSA_hash36() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 36);
        doSignVerify("NONEwithRSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    @Test
    public void testNONEwithRSA_hash40() throws Exception {
        KeyPair keyPair = generateKeyPair(getKeySize());
        byte[] sslHash = Arrays.copyOf(origMsg, 40);
        doSignVerify("NONEwithRSA", sslHash, keyPair.getPrivate(), keyPair.getPublic());
    }

    protected KeyPair generateKeyPair(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGen.initialize(keysize);
        return rsaKeyPairGen.generateKeyPair();
    }

    protected KeyPair generateKeyPairFromEncoded(int keysize) throws Exception {
        KeyPairGenerator rsaKeyPairGen = KeyPairGenerator.getInstance("RSA", getProviderName());
        rsaKeyPairGen.initialize(keysize);
        KeyPair keyPair = rsaKeyPairGen.generateKeyPair();

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());

        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA", getProviderName());

        PublicKey publicKey = rsaKeyFactory.generatePublic(x509Spec);
        PrivateKey privateKey = rsaKeyFactory.generatePrivate(pkcs8Spec);
        return new KeyPair(publicKey, privateKey);
    }

    protected KeyPair generateKeyPairFromSpec() throws Exception {
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

        KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA", getProviderName());

        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) rsaKeyFactory.generatePrivate(crtSpec);

        RSAPublicKeySpec rsaPublicSpec = new RSAPublicKeySpec(rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPublicExponent());

        RSAPublicKey rsaPublicKey = (RSAPublicKey) rsaKeyFactory.generatePublic(rsaPublicSpec);

        return new KeyPair(rsaPublicKey, rsaPrivateKey);
    }
}

