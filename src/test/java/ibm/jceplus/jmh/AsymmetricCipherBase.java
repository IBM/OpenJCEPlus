/*
 * Copyright IBM Corp. 2026
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms provided by IBM in the LICENSE file that accompanied
 * this code, including the "Classpath" Exception described therein.
 */

package ibm.jceplus.jmh;

import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

abstract public class AsymmetricCipherBase extends JMHBase {

    protected PublicKey publicKey = null;
    protected PrivateKey privateKey = null;
    protected SecureRandom random = new SecureRandom();

    /**
     * Sets a cipher test up for execution.
     * @param keySize The size of the key.
     * @param algorithm The algorithm to be used for key generation.
     * @param provider The provider to use for key generation.
     * @throws Exception
     */
    public void setup(int keySize, String algorithm, String provider)
            throws Exception {
        insertProvider(provider);

        KeyPairGenerator kpg = null;
        if (algorithm.contains("RSA")) {
            String kpgProvider = provider;
            if ("SunJCE".equalsIgnoreCase(provider)) {
                kpgProvider = "SunRsaSign";
            }
            kpg = KeyPairGenerator.getInstance("RSA", kpgProvider);
        } else {
            throw new InvalidParameterException("Benchmark not supported for: " + algorithm);
        }
        
        kpg.initialize(keySize);
        KeyPair kp = kpg.generateKeyPair();

        privateKey = kp.getPrivate();
        publicKey = kp.getPublic();
    }
}
