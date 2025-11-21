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
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class BaseTestKeySerialization extends BaseTestJunit5Signature {
    
    static final byte[] origMsg = "this is the original message to be signed".getBytes();
    static final byte[] plainText = "123456781234567812345678123456781234567812345678123456781234567".getBytes();

    @ParameterizedTest
    @CsvSource({"RSA, SHA256withRSA", "EC, SHA256withECDSA"})
    public void SerializationKeyPairTest (String algorithm, String sigAlg) throws Exception {
        KeyPairGenerator kpg = null;

        kpg = KeyPairGenerator.getInstance(algorithm, getProviderName());

        KeyPair keyPair = kpg.generateKeyPair();

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

        assertEquals(keyPair.getPrivate().getClass().getName(), 
            deserializedPrivateKey.getClass().getName(),
            "Private deserialized class does not match original");

        assertArrayEquals(keyPair.getPublic().getEncoded(), 
            deserializedPublicKey.getEncoded(),
            "Public deserialized key does not match original");

        assertArrayEquals(keyPair.getPrivate().getEncoded(), 
            deserializedPrivateKey.getEncoded(),
            "Private deserialized key does not match original");

        doSignVerify(sigAlg, origMsg, keyPair.getPrivate(), deserializedPublicKey);

        doSignVerify(sigAlg, origMsg, deserializedPrivateKey, keyPair.getPublic());

    }

    @ParameterizedTest
    @CsvSource({
        "AES, 256, AES/CBC/PKCS5Padding",
        "AES, 256, AES/GCM/NoPadding",
        "DESede, 168, DESede/CBC/PKCS5Padding",
        "ChaCha20, 256, ChaCha20/None/NoPadding"})
    public void SerializationSecretKeyTest (String algorithm, int size, String cipherName) throws Exception {
        KeyGenerator keyGen = null;
        SecretKey key = null;
        Cipher cp = null;

        //DESede and ChaCha20 not supported by FIPS provider.
        if ("OpenJCEPlusFIPS".equalsIgnoreCase(getProviderName()) && (algorithm.equalsIgnoreCase("DESede") || algorithm.equalsIgnoreCase("ChaCha20"))) {
            return;
        }

        keyGen = KeyGenerator.getInstance(algorithm, getProviderName());
        keyGen.init(size);
        key = keyGen.generateKey();

        // serialize and de-serialize the public key while storing in file
        File keyFile = createTempFile();
        serializeKey(key, keyFile);
        SecretKey deserializedKey = (SecretKey) deserializeKey(keyFile);

        assertArrayEquals(key.getEncoded(), 
            deserializedKey.getEncoded(),
            "Key deserialized key does not match original");

        cp = Cipher.getInstance(cipherName, getProviderName());
        cp.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cp.doFinal(plainText);
        
        // ChaCha20 requires special handling since it uses ChaCha20ParameterSpec instead of AlgorithmParameters
        if (algorithm.equalsIgnoreCase("ChaCha20")) {
            byte[] nonce = cp.getIV();
            ChaCha20ParameterSpec paramSpec = new ChaCha20ParameterSpec(nonce, 1);
            cp.init(Cipher.DECRYPT_MODE, deserializedKey, paramSpec);
        } else {
            AlgorithmParameters params = cp.getParameters();
            cp.init(Cipher.DECRYPT_MODE, deserializedKey, params);
        }
        
        byte[] newPlainText = cp.doFinal(cipherText, 0, cipherText.length);
        assertArrayEquals(plainText, newPlainText, "Secret keys are different");
    }

    @ParameterizedTest
    @CsvSource({"PBKDF2WithHmacSHA224", "PBKDF2WithHmacSHA256",
        "PBKDF2WithHmacSHA384", "PBKDF2WithHmacSHA512",
        "PBEWithHmacSHA1AndAES_128", "PBEWithHmacSHA1AndAES_256", "PBEWithHmacSHA224AndAES_128", "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_256", "PBEWithHmacSHA384AndAES_128", "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_128", "PBEWithHmacSHA512AndAES_256"})
    public void SerializationPBKDF2tKeyTest (String algorithm) throws Exception {
        if (algorithm.startsWith("PBE") && this.getProviderName().equalsIgnoreCase("OpenJCEPlusFIPS"))
            return;

        SecretKey key = null;
        PBEKeySpec pbeks = new PBEKeySpec("ABCDEFGHIJ".toCharArray(), new byte[32], 10000, 512);
 
        SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm, this.getProviderName());
        key = skf.generateSecret(pbeks);

        // serialize and de-serialize key while storing in file
        File keyFile = createTempFile();
        serializeKey(key, keyFile);
        SecretKey deserializedKey = (SecretKey) deserializeKey(keyFile);

        assertArrayEquals(key.getEncoded(), 
            deserializedKey.getEncoded(),
            "Key deserialized key does not match original");

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
