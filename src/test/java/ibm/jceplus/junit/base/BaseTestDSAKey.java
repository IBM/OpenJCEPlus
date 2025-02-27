/*
 * Copyright IBM Corp. 2023, 2024
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestDSAKey extends BaseTestJunit5 {
    private static String publicKey1024 = "MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7"
                                        + "s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1"
                                        + "Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnx"
                                        + "qimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHH"
                                        + "AhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKt"
                                        + "cNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFn"
                                        + "Ej6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohN"
                                        + "WLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7P"
                                        + "SSoDgYUAAoGBAKES3BYGBLgJAjVrX8E+XqGS0PISkw4XDFNRmxj"
                                        + "zYITQCn1vW6LqKIa774qZ/YMhNS+IjjmzopkUFPQRyRZr715XHg"
                                        + "ckj3wviNkjHBVb7cYLl7VSyUHujlC5O8zRtH1uaZhIXjLZ5s7Yt"
                                        + "AToIR78LByFRV5HdTroN16uGJPFi+pv";
    private static String publicKey2048 = "MIIDRzCCAjoGByqGSM44BAEwggItAoIBAQDBFbxm6EEiDWq/5Zm"
                                        + "In2/hl8Sd0piJnQBC2XV3BWeg30EVvGboQSINar/lmYifb+GXxJ"
                                        + "3SmImdAELZdXcFZ6DeQRW8ZuhBIg1qv+WZiJ9v4ZfEndKYiZ0AQ"
                                        + "tl1dwVnoN1BFbxm6EEiDWq/5ZmIn2/hl8Sd0piJnQBC2XV3BWeg"
                                        + "3EEVvGboQSINar/lmYifb+GXxJ3SmImdAELZdXcFZ6DbQRW8Zuh"
                                        + "BIg1qv+WZiJ9v4ZfEndKYiZ0AQtl1dwVnoNpBFbxm6EEiDWq/5Z"
                                        + "mIn2/hl8Sd0piJnQBC2XV3BWeg2KM+hJWvYg2zJ+dct5yoBS7Sx"
                                        + "KpOWOIZpwJmOWae8BE9AiEA6VUEEKoMDhxuHBm2jDho2QwLPA8N"
                                        + "OjKFSO2cmwFijTMCggEBAIWeQQfQ4KzgmzWm6oUv4M8bJN5Anu+"
                                        + "3K7UkhxDd6RMHj2qRUotPAY1QukNIkiH/aBFW/58qYunRja4X5r"
                                        + "nek3JsTyiFjjTt/BUwifk1h/v9hsoEKSlCLXiR2JVqlMm6MYMhD"
                                        + "mzaG0cNNCJY6ash5wTnvQqaTyCdFBS+Ng2kv6zNolPkUjWwlsBi"
                                        + "UcRcTfIYCwMq2jMz8OybxWxIUrMFUq9BX6CZf1uUY33FPMVO9gV"
                                        + "q4efm555G10qdQ1KEUd90iMfV4+pZ6tTSs/bSOKL+7uTHuiGb8Y"
                                        + "vHlvkctrp6e5eC3JjN/CoQ7TGUa0xPMC3t9rFTJzcj17hrqMpis"
                                        + "lBtDj4DggEFAAKCAQASQ0GXKor25Jebe1UXVLU8/az2HRCfD8zk"
                                        + "v30PBJYtcG3cCBBiJpM/AgRtVVYKMVJIIaUFDkU1JpcprTzJKfa"
                                        + "OlsaxuGKtKh8ps0EQBkr56/ORS/nGCvGv88ZwzfODB8/3Gazsiu"
                                        + "fQ4Ey+dhLVJrZr0qWV4ug24nMRaMr2aGjzQoFN+YGqL30DZOP2b"
                                        + "xZ/kwV0ymZ6U9HE2WQIoUc3uNpZAL9/yVenYI6J/ABNJ/+amBEn"
                                        + "2kXoKd584KEN0OW3pHvXjvq+i6ecZrBdjHHUqB/yNBwHTxVO+S8"
                                        + "alyMhRAEQFuce07a+9JlBG/Lbt2UBuRWIeFaCTfYlwpyQVM08844V";
    private static String privateKey1024 = "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt"
                                        + "9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6M"
                                        + "PbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4"
                                        + "O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3"
                                        + "RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd"
                                        + "7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBg"
                                        + "LRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/"
                                        + "C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAF"
                                        + "MO/7PSSoEFgIUCc41R8JfeJttaKod0kM2TQBnVNA=";
    private static String privateKey2048 = "MIICZQIBADCCAjoGByqGSM44BAEwggItAoIBAQDBFbxm6EEiDW"
                                        + "q/5ZmIn2/hl8Sd0piJnQBC2XV3BWeg30EVvGboQSINar/lmYifb"
                                        + "+GXxJ3SmImdAELZdXcFZ6DeQRW8ZuhBIg1qv+WZiJ9v4ZfEndKY"
                                        + "iZ0AQtl1dwVnoN1BFbxm6EEiDWq/5ZmIn2/hl8Sd0piJnQBC2XV"
                                        + "3BWeg3EEVvGboQSINar/lmYifb+GXxJ3SmImdAELZdXcFZ6DbQR"
                                        + "W8ZuhBIg1qv+WZiJ9v4ZfEndKYiZ0AQtl1dwVnoNpBFbxm6EEiD"
                                        + "Wq/5ZmIn2/hl8Sd0piJnQBC2XV3BWeg2KM+hJWvYg2zJ+dct5yo"
                                        + "BS7SxKpOWOIZpwJmOWae8BE9AiEA6VUEEKoMDhxuHBm2jDho2Qw"
                                        + "LPA8NOjKFSO2cmwFijTMCggEBAIWeQQfQ4KzgmzWm6oUv4M8bJN"
                                        + "5Anu+3K7UkhxDd6RMHj2qRUotPAY1QukNIkiH/aBFW/58qYunRj"
                                        + "a4X5rnek3JsTyiFjjTt/BUwifk1h/v9hsoEKSlCLXiR2JVqlMm6"
                                        + "MYMhDmzaG0cNNCJY6ash5wTnvQqaTyCdFBS+Ng2kv6zNolPkUjW"
                                        + "wlsBiUcRcTfIYCwMq2jMz8OybxWxIUrMFUq9BX6CZf1uUY33FPM"
                                        + "VO9gVq4efm555G10qdQ1KEUd90iMfV4+pZ6tTSs/bSOKL+7uTHu"
                                        + "iGb8YvHlvkctrp6e5eC3JjN/CoQ7TGUa0xPMC3t9rFTJzcj17hr"
                                        + "qMpislBtDj4EIgIgJGAGjgXTmTeq0L8Oo2jCuSCLmEeFfMM9xjt"
                                        +"tGLOCEc8=";

    @Test
    public void testDSAKeyGen_1024() throws Exception {
        try {
            KeyPair dsaKeyPair = generateKeyPair(1024);
            dsaKeyPair.getPublic();
            dsaKeyPair.getPrivate();
        } catch (InvalidParameterException | InvalidKeyException ikex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testDSAKeyGen_2048() throws Exception {
        KeyPair dsaKeyPair = generateKeyPair(2048);
        dsaKeyPair.getPublic();
        dsaKeyPair.getPrivate();
    }

    @Test
    public void testDSAKeyGenFromParams_1024() throws Exception {
        try {
            AlgorithmParameters algParams = generateParameters(1024);
            DSAParameterSpec dsaParameterSpec = algParams
                    .getParameterSpec(DSAParameterSpec.class);
            KeyPair dsaKeyPair = generateKeyPair(dsaParameterSpec);
            dsaKeyPair.getPublic();
            dsaKeyPair.getPrivate();
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testDSAKeyFactoryCreateFromEncoded_1024() throws Exception {
        try {

            keyFactoryCreateFromEncoded(1024);
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }
    }

    @Test
    public void testDSAKeyFactoryCreateFromEncoded_2048() throws Exception {
        keyFactoryCreateFromEncoded(2048);
    }

    @Test
    public void testDSAKeyFactoryCreateFromKeySpec_1024() throws Exception {
        try {
            keyFactoryCreateFromKeySpec(1024);
        } catch (InvalidParameterException | InvalidKeyException ipex) {
            if (getProviderName().equals("OpenJCEPlusFIPS")) {
                assertTrue(true);
            } else {
                assertTrue(false);
            }
        }

    }

    @Test
    public void testDSAKeyFactoryCreateFromKeySpec_2048() throws Exception {
        keyFactoryCreateFromKeySpec(2048);
    }

    protected AlgorithmParameters generateParameters(int size) throws Exception {
        AlgorithmParameterGenerator algParmGen = AlgorithmParameterGenerator.getInstance("DSA",
                getProviderName());
        algParmGen.init(size);
        AlgorithmParameters algParams = algParmGen.generateParameters();
        return algParams;
    }

    protected KeyPair generateKeyPair(int size) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyPairGen.initialize(size);
        KeyPair keyPair = dsaKeyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("DSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("DSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof DSAPrivateKey)) {
            fail("Private key is not a DSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof DSAPublicKey)) {
            fail("Private key is not a DSAPublicKey");
        }

        return keyPair;
    }

    protected KeyPair generateKeyPair(DSAParameterSpec dsaParameterSpec) throws Exception {
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance("DSA", getProviderName());
        dsaKeyPairGen.initialize(dsaParameterSpec);
        KeyPair keyPair = dsaKeyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("DSA Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("DSA Public key is null");
        }

        if (!(keyPair.getPrivate() instanceof DSAPrivateKey)) {
            fail("Private key is not a DSAPrivateKey");
        }

        if (!(keyPair.getPublic() instanceof DSAPublicKey)) {
            fail("Private key is not a DSAPublicKey");
        }

        return keyPair;
    }

    protected KeyPair keyFactoryCreateFromEncoded(int size) throws Exception {
        byte[] publicKeyArray = null;
        byte[] privateKeyArray = null;
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            if (size == 1024) {
                publicKeyArray = Base64.getDecoder().decode(publicKey1024);
                privateKeyArray = Base64.getDecoder().decode(privateKey1024);
            } else if (size == 2048) {
                publicKeyArray = Base64.getDecoder().decode(publicKey2048);
                privateKeyArray = Base64.getDecoder().decode(privateKey2048);
            } else {
                fail("Unsupported size for keyFactoryCreateFromEncoded method");
            }
        } else {
            KeyPair dsaKeyPair = generateKeyPair(size);
            publicKeyArray = dsaKeyPair.getPublic().getEncoded();
            privateKeyArray = dsaKeyPair.getPrivate().getEncoded();
        }

        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(publicKeyArray);
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(privateKeyArray);

        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA", getProviderName());
        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(x509Spec);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(dsaPub.getEncoded(), publicKeyArray)) {
            fail("DSA public key does not match generated public key");
        }

        if (!Arrays.equals(dsaPriv.getEncoded(), privateKeyArray)) {
            fail("DSA private key does not match generated public key");
        }

        return new KeyPair(dsaPub, dsaPriv);
    }

    protected void keyFactoryCreateFromKeySpec(int size) throws Exception {

        KeyPair dsaKeyPair = keyFactoryCreateFromEncoded(size);

        KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA", getProviderName());
        DSAPublicKeySpec dsaPubSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPublic(), DSAPublicKeySpec.class);
        DSAPublicKey dsaPub = (DSAPublicKey) dsaKeyFactory.generatePublic(dsaPubSpec);

        if (!Arrays.equals(dsaPub.getEncoded(), dsaKeyPair.getPublic().getEncoded())) {
            fail("DSA public key does not match generated public key");
        }

        DSAPrivateKeySpec dsaPrivateSpec = dsaKeyFactory
                .getKeySpec(dsaKeyPair.getPrivate(), DSAPrivateKeySpec.class);
        DSAPrivateKey dsaPriv = (DSAPrivateKey) dsaKeyFactory.generatePrivate(dsaPrivateSpec);

        if (!Arrays.equals(dsaPriv.getEncoded(), dsaKeyPair.getPrivate().getEncoded())) {
            fail("DSA private key does not match generated private key");
        }
    }
}
