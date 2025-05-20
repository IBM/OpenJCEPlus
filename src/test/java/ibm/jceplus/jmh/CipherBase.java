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

    protected byte[] plaintext = null;
    protected SecretKey secretKey = null;
    protected IvParameterSpec iv = null;
    protected GCMParameterSpec gcmParm = null;
    ChaCha20ParameterSpec chacha20Spec = null;
    protected Cipher encryptCipher = null;
    protected Cipher decryptCipher = null;
    protected byte[] ciphertext = null;
    protected SecureRandom random = new SecureRandom();

    /**
     * Sets a cipher test up for execution.
     * @param keySize The size of the key.
     * @param transformation The transformation.
     * @param payloadSize The payload to preallocate with random data. This value may be 0 in which we will not use a payload such as AESWraping.
     * @param provider The provider to use for both key generation and the transformation itself.
     * @throws Exception
     */
    public void setup(int keySize, String transformation, int payloadSize, String provider)
            throws Exception {
        insertProvider(provider);
        String splitTransformation[] = transformation.split("/");

        String algorithm = splitTransformation[0];

        String mode = null;
        if (splitTransformation.length > 1) {
            mode = splitTransformation[1];
        }

        encryptCipher = Cipher.getInstance(transformation, provider);
        decryptCipher = Cipher.getInstance(transformation, provider);

        plaintext = new byte[payloadSize];
        random.nextBytes(plaintext);

        KeyGenerator keyGen = null;
        if (algorithm.equals("ChaCha20-Poly1305")) {
            keyGen = KeyGenerator.getInstance("ChaCha20", provider);
        } else if (algorithm.startsWith("AESWrap")) {
            keyGen = KeyGenerator.getInstance("AES", provider);
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

        if (plaintext.length > 0) {
            ciphertext = encryptCipher.doFinal(plaintext);
        }
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
        return "CBC".equals(mode) || "CFB".equals(mode) || "CTR".equals(mode) || "GCM".equals(mode)
                || "None".equals(mode) || // ChaCha20 specific
                "OFB".equals(mode);
    }
}
