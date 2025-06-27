/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */
package ibm.jceplus.junit.base;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.KEM;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestPQCKeySerialization extends BaseTestJunit5 {
    
    final String PQCKEM_KEYAGREEMENT_ALG = "MLKEMKeyAgreement";
    String algorithm = "ML_KEM_768";

    @Test
    public void SerializationTest () throws Exception {
        KeyPairGenerator kpg = null;

        try {
            kpg = KeyPairGenerator.getInstance(algorithm, getProviderName());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw e;
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            throw e;
        }

        KeyPair keyPair = kpg.generateKeyPair();

        KEM kem = KEM.getInstance(algorithm, getProviderName());

        // serialize and de-serialize the public key while storing in file
        File publicKeyFile = createTempFile();
        serializeKey(keyPair.getPublic(), publicKeyFile);
        PublicKey deserializedPublicKey = (PublicKey) deserializeKey(publicKeyFile);

        // private key serialize and de-serialize
        File privateKeyFile = createTempFile();
        serializeKey(keyPair.getPrivate(), privateKeyFile);
        PrivateKey deserializedPrivateKey = (PrivateKey) deserializeKey(privateKeyFile);

        assertEquals(keyPair.getPublic().getClass().getName(), 
            deserializedPublicKey.getClass().getName(),
            "Public deserialized class does not match original");

        assertEquals(keyPair.getPublic().getClass().getName(), 
            deserializedPublicKey.getClass().getName(),
            "Public deserialized class does not match original");

        assertArrayEquals(keyPair.getPublic().getEncoded(), 
            deserializedPublicKey.getEncoded(),
            "Public deserialized key does not match original");

        assertArrayEquals(keyPair.getPrivate().getEncoded(), 
            deserializedPrivateKey.getEncoded(),
            "Private deserialized key does not match original");

        KEM.Encapsulator encr = kem.newEncapsulator(keyPair.getPublic());
        KEM.Encapsulated enc = encr.encapsulate(0,31,"AES");

        SecretKey keyE = enc.key();

        KEM.Decapsulator decr = kem.newDecapsulator(deserializedPrivateKey);
        SecretKey keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");

        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");

        encr = kem.newEncapsulator(deserializedPublicKey);
        enc = encr.encapsulate(0,31,"AES");

        keyE = enc.key();

        decr = kem.newDecapsulator(keyPair.getPrivate());
        keyD = decr.decapsulate(enc.encapsulation(),0,31,"AES");

        assertArrayEquals(keyE.getEncoded(),keyD.getEncoded(),"Secrets do NOT match");
    }

    protected KeyPair generateKeyPair(KeyPairGenerator keyPairGen) throws Exception {
        KeyPair keyPair = keyPairGen.generateKeyPair();

        if (keyPair.getPrivate() == null) {
            fail("Private key is null");
        }

        if (keyPair.getPublic() == null) {
            fail("Public key is null");
        }

        return keyPair;
    }

    private File createTempFile() {
        File file = null;
        try {
            file = File.createTempFile("key", ".ser");
            return file;
        } catch (IOException e) {
            fail("temporary file cannot be created");
        }
        return file;
    }

    private boolean destroyFile(File file) {
        return file.delete();
    }

    private void serializeKey(Object key, File file) {
        try (ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(file))) {
            objectOutputStream.writeObject(key);
        } catch (IOException e) {
            file.deleteOnExit();
            fail("Error during serialization: " + e.getMessage());
        }
    }

    private Object deserializeKey(File file) {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(file))) {
            Object object = objectInputStream.readObject();
            return object;
        } catch (IOException | ClassNotFoundException e) {
            file.deleteOnExit();
            fail("Error during deserialization: " + e.getMessage());
        }
        return null;
    }
}    
