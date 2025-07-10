/*
 * Copyright IBM Corp. 2025
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

abstract public class CipherBase extends JMHBase {

    protected byte[] plaintext;
    protected SecretKey secretKey;
    protected IvParameterSpec iv;
    protected GCMParameterSpec gcmParm;
    ChaCha20ParameterSpec chacha20Spec;
    protected Cipher encryptCipher;
    protected Cipher decryptCipher;
    protected byte[] ciphertext;
    protected SecureRandom random = new SecureRandom();

    public void setup(int keySize, String transformation, int payloadSize, String provider) throws Exception {
        insertProvider(provider);

        String algorithm = transformation.split("/")[0];
        String mode = transformation.split("/")[1];
        encryptCipher = Cipher.getInstance(transformation, provider);
        decryptCipher = Cipher.getInstance(transformation, provider);
        
        plaintext = new byte[payloadSize];
        random.nextBytes(plaintext);

        KeyGenerator keyGen = null;
        if (algorithm.equals("ChaCha20-Poly1305")) {
            keyGen = KeyGenerator.getInstance("ChaCha20", provider);
        } else {
            keyGen = KeyGenerator.getInstance(algorithm, provider);
        }
        keyGen.init(keySize);
        secretKey = keyGen.generateKey();

        iv = null;
        gcmParm = null;
        if (ivRequired(mode)) {
            byte[] ivBytes = new byte[getIVSize(algorithm, mode)];
            random.nextBytes(ivBytes);
            if (mode.equals("GCM")) {
                int tagLength = 128;
                gcmParm = new GCMParameterSpec(tagLength, ivBytes);
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParm);
            } else if (algorithm.equals("ChaCha20")) {
                chacha20Spec = new ChaCha20ParameterSpec(ivBytes, 1);
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, chacha20Spec);
            } else {
                iv = new IvParameterSpec(ivBytes);
                encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            }
        } else {
            encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        }

        ciphertext = encryptCipher.doFinal(plaintext);
    }

    protected int getIVSize(String algorithm, String mode) {
        if ("AES".equals(algorithm)) {
            return "GCM".equals(mode) ? 12 : 16;
        } else if ("DESede".equals(algorithm)) {
            return 8;
        } else if (algorithm.startsWith("ChaCha20")) {
            return 12;
        }
        return 16;
    }

    private boolean ivRequired(String mode) {
        return "CBC".equals(mode) ||
               "CFB".equals(mode) ||
               "CTR".equals(mode) ||
               "GCM".equals(mode) ||
               "None".equals(mode) || // ChaCha20 specific
               "OFB".equals(mode);
    }
}
