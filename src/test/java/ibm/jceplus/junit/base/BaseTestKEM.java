/*
 * Copyright IBM Corp. 2025
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
<<<<<<< HEAD
import java.util.Arrays;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertTrue;
=======
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestKEM extends BaseTestJunit5 {


    protected KeyPairGenerator pqcKeyPairGen;
    protected KeyFactory pqcKeyFactory;

<<<<<<< HEAD
    @BeforeEach
    public void setUp() throws Exception {

    }

=======
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
    public void testKEM(String Algorithm) throws Exception {
        if (getProviderName().equals("OpenJCEPlusFIPS")) {
            //FIPS does not support PQC keys currently
            return;
        }
        KEM kem = KEM.getInstance(Algorithm, getProviderName());

        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        pqcKeyPair.getPublic();
        pqcKeyPair.getPrivate();

        KEM.Encapsulator encr = kem.newEncapsulator(pqcKeyPair.getPublic());
<<<<<<< HEAD
        KEM.Encapsulated enc = encr.encapsulate(0,32,"AES");
=======
        KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210

        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kem.newDecapsulator(pqcKeyPair.getPrivate());
<<<<<<< HEAD
        SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,32,"AES");
         
        assertTrue(Arrays.equals(keyE.getEncoded(), keyD.getEncoded()), "Secrets do NOT match");
=======
        SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");
        
        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
    }

    protected KeyPair generateKeyPair(String Algorithm) throws Exception {
        pqcKeyPairGen = KeyPairGenerator.getInstance(Algorithm, getProviderName());

        KeyPair keyPair = pqcKeyPairGen.generateKeyPair();
        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("RPublic key is null");
        }

        if (!(keyPair.getPrivate() instanceof PrivateKey)) {
            fail("Key is not a PrivateKey");
        }

        if (!(keyPair.getPublic() instanceof PublicKey)) {
            fail("Key is not a PublicKey");
        }

        return keyPair;
    }

<<<<<<< HEAD

=======
    @ParameterizedTest
    @CsvSource({"ML-KEM-512","ML_KEM_768","ML_KEM_1024"})
>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
    protected void keyFactoryCreateFromEncoded(String Algorithm) throws Exception {

        pqcKeyFactory = KeyFactory.getInstance(Algorithm, getProviderName());
        KeyPair pqcKeyPair = generateKeyPair(Algorithm);
        
        X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pqcKeyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(
                pqcKeyPair.getPrivate().getEncoded());

<<<<<<< HEAD
        PublicKey rsaPub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey rsaPriv =  pqcKeyFactory.generatePrivate(pkcs8Spec);

        if (!Arrays.equals(rsaPub.getEncoded(), pqcKeyPair.getPublic().getEncoded())) {
            fail("RSA public key does not match generated public key");
        }

        if (!Arrays.equals(rsaPriv.getEncoded(), pqcKeyPair.getPrivate().getEncoded())) {
            fail("RSA private key does not match generated public key");
        }
=======
        PublicKey pub =  pqcKeyFactory.generatePublic(x509Spec);
        PrivateKey priv =  pqcKeyFactory.generatePrivate(pkcs8Spec);


        assertArrayEquals(pub.getEncoded(),pqcKeyPair.getPublic().getEncoded(),"Public key does not match generated public key");
        assertArrayEquals(priv.getEncoded(),pqcKeyPair.getPrivate().getEncoded(),"Private key does not match generated public key");

>>>>>>> 307ca5d8a73e66a1dd890e1c2c14208a5c82f210
    }
}

